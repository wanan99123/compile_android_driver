#include "gs_mem.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/mm.h>
#include <net/sock.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/sched/mm.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <asm/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jayne");
MODULE_DESCRIPTION("High performance kernel memory r/w");
MODULE_VERSION("1.0");

struct sock *nl_sk;

static __always_inline struct mm_struct *get_mm_by_pid(pid_t nr)
{
    struct task_struct *task = pid_task(find_vpid(nr), PIDTYPE_PID);
    if (!task)
        return NULL;
    return get_task_mm(task);
}

static __always_inline uintptr_t
get_module_base(struct mm_struct *mm, const char *name)
{
    struct vm_area_struct *vma;
    char buf[ARC_PATH_MAX];

    if (!mm || !name)
        return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
    struct vma_iterator vmi;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        const char *path_nm;

        if (!vma->vm_file)
            continue;

        path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX);
        if (IS_ERR(path_nm))
            continue;

        if (!strcmp(kbasename(path_nm), name))
            return vma->vm_start;
    }
    return 0;
}

static __always_inline phys_addr_t
translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd = pgd_offset(mm, va);

    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
    p4d_t *p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;
    pud_t *pud = pud_offset(p4d, va);
#else
    pud_t *pud = pud_offset(pgd, va);
#endif

    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    pmd_t *pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd))
        return 0;

    pte_t *pte = pte_offset_kernel(pmd, va);
    if (!pte_present(*pte))
        return 0;

    return (pte_pfn(*pte) << PAGE_SHIFT) | (va & (PAGE_SIZE - 1));
}

static __always_inline void
read_phys_addr(void __user *base, phys_addr_t pa, size_t len)
{
    // 改为非缓存映射
    void __iomem *ka = ioremap_nocache(pa, len);
    if (!ka)
        return;

    (void)__copy_to_user(base, ka, len);
    iounmap(ka);
}

static __always_inline void
write_phys_addr(void __user *base, phys_addr_t pa, size_t len)
{
    // 改为非缓存映射
    void __iomem *ka = ioremap_nocache(pa, len);
    if (!ka)
        return;

    (void)__copy_from_user(ka, base, len);
    iounmap(ka);
}

static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    struct process_info *info = nlmsg_data(nlh);
    struct mm_struct *mm;

    mm = get_mm_by_pid(info->pid);
    if (!mm)
        return;

    if (info->type == 2) {
        uintptr_t base = get_module_base(mm, info->module_name);
        (void)__copy_to_user(info->base, &base, info->len);
        mmput(mm);
        return;
    }

    phys_addr_t pa = translate_linear_address(mm, info->virt_addr);

    if (info->type == 0)
        read_phys_addr(info->base, pa, info->len);
    else if (info->type == 1)
        write_phys_addr(info->base, pa, info->len);

    mmput(mm);
}

static int __init gs_mem_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = nl_recv_msg,
        .groups = 0,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM_PROTOCOL, &cfg);
    if (!nl_sk)
        return -ENOMEM;

    // 隐匿性处理（可选）
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    THIS_MODULE->sect_attrs = NULL;
    THIS_MODULE->notes_attrs = NULL;

    return 0;
}

static void __exit gs_mem_exit(void)
{
    if (nl_sk)
        netlink_kernel_release(nl_sk);
}

module_init(gs_mem_init);
module_exit(gs_mem_exit);
