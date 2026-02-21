#include <linux/init.h>
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
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/highmem.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
#include <linux/io.h>
#endif

#include "gs_mem.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jayne");
MODULE_DESCRIPTION("通用兼容的内存读写模块");
MODULE_VERSION("1.0");

static struct sock *nl_sk = NULL;
static struct netlink_kernel_cfg cfg;
static struct process_info *process_info_data;

static inline struct mm_struct *get_mm_by_pid(pid_t nr);
static inline struct mm_struct *get_mm_by_pid(pid_t nr)
{
    struct task_struct *task;

    task = pid_task(find_vpid(nr), PIDTYPE_PID);
    if (!task)
        return NULL;

    return get_task_mm(task);
}

uintptr_t get_module_base(struct mm_struct* mm, char* name);

uintptr_t get_module_base(struct mm_struct* mm, char* name) 
{
    struct vm_area_struct *vma;

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        char buf[MAX_ADDR_LEN];
        char *path_nm = "";

        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, MAX_ADDR_LEN-1);
            if (!strcmp(kbasename(path_nm), name)) {
                return vma->vm_start;
            }
        }
    }
    return 0;
}

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va);

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {

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
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
    // 支持五级页表的内核 (4.11+)
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
    	return 0;
    }
    pud = pud_offset(p4d, va);
#else
    // 旧内核直接使用 pgd 作为 pud
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
    
    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE-1);
    
    return page_addr + page_offset;
}

void read_phys_addr(void *base, phys_addr_t phys_addr, void* kernel_addr, size_t len);
void read_phys_addr(void *base, phys_addr_t phys_addr, void* kernel_addr, size_t len) {
    if (!phys_addr) {
        printk(KERN_ERR "v2p: read_phys_addr获取phys_addr 出错\n");
        return;
    }

    if (!pfn_valid(__phys_to_pfn(phys_addr))) {
        return;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    // 5.11+ 使用 memremap
    kernel_addr = memremap(phys_addr, len, MEMREMAP_WB);
#else
    // 旧内核使用 ioremap_cache
    kernel_addr = ioremap_cache(phys_addr, len);
#endif

    if(!kernel_addr) {
        printk(KERN_ERR "v2p: read_phys_addr获取 kernel_addr 出错\n");
        return;
    }
    
    if(copy_to_user(base, kernel_addr, len)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
        memunmap(kernel_addr);
#else
        iounmap(kernel_addr);
#endif
        return;
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    memunmap(kernel_addr);
#else
    iounmap(kernel_addr);
#endif
}

void write_phys_addr(void *base, phys_addr_t phys_addr, void* kernel_addr, size_t len);
void write_phys_addr(void *base, phys_addr_t phys_addr, void* kernel_addr, size_t len) {
    if (!phys_addr) {
        printk(KERN_ERR "v2p: write_phys_addr获取phys_addr 出错\n");
        return;
    }

    if (!pfn_valid(__phys_to_pfn(phys_addr))) {
        return;
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    // 5.11+ 使用 memremap
    kernel_addr = memremap(phys_addr, len, MEMREMAP_WB);
#else
    // 旧内核使用 ioremap_cache
    kernel_addr = ioremap_cache(phys_addr, len);
#endif

    if(!kernel_addr) {
        printk(KERN_ERR "v2p: write_phys_addr获取 kernel_addr 出错\n");
        return;
    }
    
    if(copy_from_user(kernel_addr, base, len)) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
        memunmap(kernel_addr);
#else
        iounmap(kernel_addr);
#endif
        return;
    }
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    memunmap(kernel_addr);
#else
    iounmap(kernel_addr);
#endif
}

static void nl_recv_msg(struct sk_buff *skb) {
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
    char kernel_module_name[MAX_ADDR_LEN];
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
        printk(KERN_ERR "v2p: 获取mm 出错\n");
        return;
    }
    mmput(mm);

    if(type == 2) {
        ret = copy_from_user(kernel_module_name, process_info_data->module_name, 
                sizeof(kernel_module_name));
        ptr = get_module_base(mm, kernel_module_name);
        printk(KERN_INFO "v2p name: %s, ptr: %lx\n", kernel_module_name, ptr);
        ret = copy_to_user(base, &ptr, len);
        return;
    }

    virt_addr = process_info_data->virt_addr;
    phys_addr = translate_linear_address(mm, virt_addr);

    if(type == 0) {
        read_phys_addr(base, phys_addr, kernel_addr, len);
    } else if(type == 1) {
        write_phys_addr(base, phys_addr, kernel_addr, len);
    }
}

static int __init netlink_virt_to_phys_init(void) {
    printk(KERN_INFO "v2p: Loading netlink_virt_to_phys module...\n");

    cfg.input = nl_recv_msg;

    // 内核版本兼容性处理
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    // 6.x 内核使用 __netlink_kernel_create
    nl_sk = __netlink_kernel_create(&init_net, NETLINK_CUSTOM_PROTOCOL, THIS_MODULE, &cfg);
#else
    // 5.x 及以下内核使用 netlink_kernel_create
    nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM_PROTOCOL, &cfg);
#endif

    if (!nl_sk) {
        printk(KERN_ALERT "v2p: Error creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit netlink_virt_to_phys_exit(void) {
    printk(KERN_INFO "v2p: Unloading netlink_virt_to_phys module...\n");

    if (nl_sk) {
        netlink_kernel_release(nl_sk);
    }
}

module_init(netlink_virt_to_phys_init);
module_exit(netlink_virt_to_phys_exit);
