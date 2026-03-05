/*
 * 内核级物理内存读取模块
 * 通过Netlink与用户态通信
 */

// ==================== 宏与结构体定义 ====================
#define NETLINK_CUSTOM_PROTOCOL 20
#define ARC_PATH_MAX 256
#define GS_MAX_MODULE_NAME_LEN 256

struct process_info {
    pid_t pid;
    size_t virt_addr;
    size_t len;
    void *base;
    int type;
    char *module_name;
};

// ==================== 头文件包含 ====================
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/ptrace.h>
#include <linux/seq_file.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/highmem.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/mmzone.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jayne");
MODULE_DESCRIPTION("一个通过Netlink调用内核模块实现内核级物理内存读取的简单示例");
MODULE_VERSION("0.1");

// ==================== 全局变量 ====================
struct sock *nl_sk = NULL;
struct netlink_kernel_cfg cfg;
struct process_info *process_info_data;

// ==================== 辅助函数 ====================

/**
 * @brief 根据PID获取进程的mm_struct
 */
static inline struct mm_struct *get_mm_by_pid(pid_t nr)
{
    struct task_struct *task = pid_task(find_vpid(nr), PIDTYPE_PID);
    if (!task)
        return NULL;
    return get_task_mm(task);
}

/**
 * @brief 获取指定模块在进程中的基地址
 */
uintptr_t get_module_base(struct mm_struct *mm, char *name)
{
    struct vm_area_struct *vma;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX - 1);
            if (!strcmp(kbasename(path_nm), name)) {
                return vma->vm_start;
            }
        }
    }
    return 0;
}

/**
 * @brief 线性地址转物理地址
 */
phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    pud = pud_offset(p4d, va);
#else
    pud = pud_offset(pgd, va);
#endif

    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;

    pte = pte_offset_kernel(pmd, va);
    if (pte_none(*pte) || !pte_present(*pte))
        return 0;

    // 计算物理地址
    phys_addr_t page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    uintptr_t page_offset = va & (PAGE_SIZE - 1);
    return page_addr + page_offset;
}

/**
 * @brief 从物理地址读取数据
 */
void read_phys_addr(void *base, phys_addr_t phys_addr, void *kernel_addr, size_t len)
{
    if (!phys_addr || !pfn_valid(__phys_to_pfn(phys_addr)))
        return;

    kernel_addr = ioremap_cache(phys_addr, len);
    if (!kernel_addr)
        return;

    copy_to_user(base, kernel_addr, len);
    iounmap(kernel_addr);
}

/**
 * @brief 向物理地址写入数据
 */
void write_phys_addr(void *base, phys_addr_t phys_addr, void *kernel_addr, size_t len)
{
    if (!phys_addr || !pfn_valid(__phys_to_pfn(phys_addr)))
        return;

    kernel_addr = ioremap_cache(phys_addr, len);
    if (!kernel_addr)
        return;

    copy_from_user(kernel_addr, base, len);
    iounmap(kernel_addr);
}

// ==================== Netlink 回调 ====================

/**
 * @brief Netlink消息处理
 */
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
    process_info_data = (struct process_info *)nlmsg_data(nlh);

    int pid = process_info_data->pid;
    int type = process_info_data->type;
    size_t len = process_info_data->len;
    void *base = process_info_data->base;

    struct mm_struct *mm = get_mm_by_pid(pid);
    if (!mm) return;

    if (type == 2) {
        // 获取模块基地址
        char kernel_module_name[GS_MAX_MODULE_NAME_LEN];
        if (copy_from_user(kernel_module_name, process_info_data->module_name, sizeof(kernel_module_name))) {
            mmput(mm);
            return;
        }

        uintptr_t ptr = get_module_base(mm, kernel_module_name);
        copy_to_user(base, &ptr, len);
    } else {
        // 内存读写
        size_t virt_addr = process_info_data->virt_addr;
        phys_addr_t phys_addr = translate_linear_address(mm, virt_addr);

        if (type == 0)
            read_phys_addr(base, phys_addr, NULL, len);
        else if (type == 1)
            write_phys_addr(base, phys_addr, NULL, len);
    }

    mmput(mm);
}

// ==================== 模块入口 ====================

static int __init netlink_virt_to_phys_init(void)
{
    // 配置Netlink
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = nl_recv_msg;
    nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM_PROTOCOL, &cfg);
    if (!nl_sk) return -ENOMEM;

    // 隐藏模块（Rootkit特性）
    struct module *mod = THIS_MODULE;
    list_del_init(&mod->list);
    kobject_del(&mod->mkobj.kobj);
    mod->sect_attrs = NULL;
    mod->notes_attrs = NULL;

    return 0;
}

static void __exit netlink_virt_to_phys_exit(void)
{
    if (nl_sk) netlink_kernel_release(nl_sk);
}

module_init(netlink_virt_to_phys_init);
module_exit(netlink_virt_to_phys_exit);
