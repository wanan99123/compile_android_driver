#include "gs_mem.h"
#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <linux/sched/mm.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/mman.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jayne");
MODULE_DESCRIPTION("Full compat physmem v2p");
MODULE_VERSION("1.0");

struct sock *nl_sk = NULL;
static struct process_info *process_info_data;

static inline struct mm_struct *get_mm_by_pid(pid_t nr)
{
    struct task_struct *task;
    struct mm_struct *mm = NULL;

    rcu_read_lock();
    task = pid_task(find_vpid(nr), PIDTYPE_PID);
    if (task)
        mm = get_task_mm(task);
    rcu_read_unlock();

    return mm;
}

uintptr_t get_module_base(struct mm_struct *mm, const char *name)
{
    struct vm_area_struct *vma;
    char buf[256];
    const char *path;

    if (!mm || !name)
        return 0;

    mmap_read_lock(mm);
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (!vma->vm_file)
            continue;

        path = file_path(vma->vm_file, buf, sizeof(buf)-1);
        if (!strcmp(kbasename(path), name)) {
            uintptr_t ret = vma->vm_start;
            mmap_read_unlock(mm);
            return ret;
        }
    }
    mmap_read_unlock(mm);
    return 0;
}

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    if (!mm)
        return 0;

    pgd = pgd_offset(mm, va);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return 0;

    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return 0;

    pud = pud_offset(p4d, va);
    if (pud_none(*pud) || pud_bad(*pud))
        return 0;

    pmd = pmd_offset(pud, va);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return 0;

    pte = pte_offset_kernel(pmd, va);
    if (!pte || pte_none(*pte) || !pte_present(*pte))
        return 0;

    return (phys_addr_t)pte_pfn(*pte) << PAGE_SHIFT | (va & ~PAGE_MASK);
}

void read_phys_addr(void __user *base, phys_addr_t phys_addr, size_t len)
{
    void *kaddr;
    unsigned long ret;

    if (!base || !phys_addr || !len)
        return;

    if (!pfn_valid(__phys_to_pfn(phys_addr)))
        return;

    kaddr = ioremap_cache(phys_addr, len);
    if (!kaddr)
        return;

    ret = copy_to_user(base, kaddr, len);
    (void)ret;

    iounmap(kaddr);
}

void write_phys_addr(void __user *base, phys_addr_t phys_addr, size_t len)
{
    void *kaddr;
    unsigned long ret;

    if (!base || !phys_addr || !len)
        return;

    if (!pfn_valid(__phys_to_pfn(phys_addr)))
        return;

    kaddr = ioremap_cache(phys_addr, len);
    if (!kaddr)
        return;

    ret = copy_from_user(kaddr, base, len);
    (void)ret;

    iounmap(kaddr);
}

static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    struct process_info *info = nlmsg_data(nlh);
    struct mm_struct *mm;
    phys_addr_t pa;
    uintptr_t mod_base;

    if (!info)
        return;

    mm = get_mm_by_pid(info->pid);
    if (!mm) {
        pr_err("v2p: get mm failed\n");
        return;
    }

    if (info->type == 2) {
        mod_base = get_module_base(mm, info->module_name);
        pr_info("v2p: %s base = %lx\n", info->module_name, mod_base);
        copy_to_user(info->base, &mod_base, info->len);
        mmput(mm);
        return;
    }

    pa = translate_linear_address(mm, info->virt_addr);

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
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM_PROTOCOL, &cfg);
    if (!nl_sk) {
        pr_err("netlink create failed\n");
        return -ENOMEM;
    }

    pr_info("gs_mem loaded\n");
    return 0;
}

static void __exit gs_mem_exit(void)
{
    netlink_kernel_release(nl_sk);
    pr_info("gs_mem unloaded\n");
}

module_init(gs_mem_init);
module_exit(gs_mem_exit);
