#include "gs_mem.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <net/sock.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/sched/mm.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/highmem.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/errno.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jayne");
MODULE_DESCRIPTION("一个通过Netlink调用内核模块实现内核级物理内存读取的简单示例");
MODULE_VERSION("0.1");

// 全局变量定义
struct sock *nl_sk = NULL;
struct netlink_kernel_cfg cfg;
struct process_info *process_info_data;

// 根据进程ID获取进程的内存管理结构体
static inline struct mm_struct *get_mm_by_pid(pid_t nr)
{
    struct task_struct *task;

    task = pid_task(find_vpid(nr), PIDTYPE_PID);
    if (!task)
        return NULL;

    return get_task_mm(task);
}

// 获取模块基地址
uintptr_t get_module_base(struct mm_struct* mm, char* name)
{
    struct vm_area_struct *vma;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    // 6.x内核 - 使用vma_iterator
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    // 5.x及以下内核
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX-1);
            if (!strcmp(kbasename(path_nm), name)) {
                return vma->vm_start;
            }
        }
    }
    return 0;
}

// 线性地址转物理地址
phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
    
    phys_addr_t page_addr;
    uintptr_t page_offset;
    
    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
        return 0;
    }
    pud = pud_offset(p4d, va);
#else
    pud = pud_offset(pgd, va);
#endif
    
    if(pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
    
    pmd = pmd_offset(pud, va);
    if(pmd_none(*pmd)) {
        return 0;
    }
    
    pte = pte_offset_kernel(pmd, va);
    if(pte_none(*pte)) {
        return 0;
    }
    
    if(!pte_present(*pte)) {
        return 0;
    }
    
    // 页物理地址
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    // 页内偏移
    page_offset = va & (PAGE_SIZE-1);
    
    return page_addr + page_offset;
}

// 从物理地址读取数据
void read_phys_addr(void *base, phys_addr_t phys_addr, void* kernel_addr, size_t len)
{
    if (!phys_addr) {
      //  printk(KERN_ERR "v2p: read_phys_addr获取phys_addr 出错\n");
        return;
    }

    if (!pfn_valid(__phys_to_pfn(phys_addr))) {
        return;
    }
    
    kernel_addr = ioremap_cache(phys_addr, len);
    if(!kernel_addr){
       // printk(KERN_ERR "v2p: read_phys_addr获取 kernel_addr 出错\n");
        return;
    }
    
    if(copy_to_user(base, kernel_addr, len)) {
      //  printk(KERN_ERR "v2p: copy_to_user失败\n");
    }
    
    iounmap(kernel_addr);
}

// 向物理地址写入数据
void write_phys_addr(void *base, phys_addr_t phys_addr, void* kernel_addr, size_t len)
{
    if (!phys_addr) {
       // printk(KERN_ERR "v2p: write_phys_addr获取phys_addr 出错\n");
        return;
    }

    if (!pfn_valid(__phys_to_pfn(phys_addr))) {
        return;
    }
    
    kernel_addr = ioremap_cache(phys_addr, len);
    if(!kernel_addr){
     //   printk(KERN_ERR "v2p: write_phys_addr获取 kernel_addr 出错\n");
        return;
    }
    
    if(copy_from_user(kernel_addr, base, len)) {
       // printk(KERN_ERR "v2p: copy_from_user失败\n");
    }
    
    iounmap(kernel_addr);
}

// 接收Netlink消息的回调函数
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    int send_pid;
    size_t virt_addr;
    phys_addr_t phys_addr;
    void* kernel_addr = NULL;
    size_t len;
    struct mm_struct *mm;
    void *base;
    int type;
    char kernel_module_name[GS_MAX_MODULE_NAME_LEN];
    uintptr_t ptr;
    ssize_t ret;

    nlh = (struct nlmsghdr *)skb->data;
    send_pid = nlh->nlmsg_pid;

    process_info_data = (struct process_info *)nlmsg_data(nlh);
    pid = process_info_data->pid;
    len = process_info_data->len;
    base = process_info_data->base;
    type = process_info_data->type;

    mm = get_mm_by_pid(pid);
    if (!mm) {
        //printk(KERN_ERR "v2p: 获取mm 出错\n");
        return;
    }

    if(type == 2) {
        ret = copy_from_user(kernel_module_name, process_info_data->module_name, 
                            sizeof(kernel_module_name));
        if (ret) {
           // printk(KERN_ERR "v2p: copy_from_user失败\n");
            mmput(mm);
            return;
        }
        
        ptr = get_module_base(mm, kernel_module_name);
       // printk(KERN_INFO "v2p name: %s,ptr: %lx\n", kernel_module_name, ptr);
        
        ret = copy_to_user(base, &ptr, len);
        if (ret) {
          //  printk(KERN_ERR "v2p: copy_to_user失败\n");
        }
        
        mmput(mm);
        return;
    }

    virt_addr = process_info_data->virt_addr;
    phys_addr = translate_linear_address(mm, virt_addr);
    
    if(type == 0) {
        read_phys_addr(base, phys_addr, kernel_addr, len);
    } else if(type == 1) {
        write_phys_addr(base, phys_addr, kernel_addr, len);
    }
    
    mmput(mm);
}

// 模块初始化函数
static int __init netlink_virt_to_phys_init(void)
{
    struct module *mod;
    
   // printk(KERN_INFO "v2p: Loading netlink_virt_to_phys module...\n");

    memset(&cfg, 0, sizeof(cfg));
    cfg.input = nl_recv_msg;
    cfg.groups = 0;

    nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM_PROTOCOL, &cfg);
    if (!nl_sk) {
       // printk(KERN_ALERT "v2p: Error creating socket.\n");
        return -ENOMEM;
    }

    // 隐藏模块（可选，如果不需要可以注释掉）
    mod = THIS_MODULE;
    
    // 从模块列表中删除
    list_del_init(&mod->list);
    
    // 删除sysfs中的kobject
    kobject_del(&mod->mkobj.kobj);
    
    // 清空其他属性
    mod->sect_attrs = NULL;
    mod->notes_attrs = NULL;
    
   // printk(KERN_INFO "v2p: Module loaded and hidden successfully.\n");

    return 0;
}

// 模块卸载函数
static void __exit netlink_virt_to_phys_exit(void)
{
  //  printk(KERN_INFO "v2p: Unloading netlink_virt_to_phys module...\n");

    if (nl_sk) {
        netlink_kernel_release(nl_sk);
    }
}

module_init(netlink_virt_to_phys_init);
module_exit(netlink_virt_to_phys_exit);
