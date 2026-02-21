#include "gs_mem.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jayne");
MODULE_DESCRIPTION("Netlink 内核物理内存读写");
MODULE_VERSION("0.1");

#define NETLINK_CUSTOM_PROTOCOL 31

struct sock *nl_sk = NULL;
struct netlink_kernel_cfg cfg = {
    .input = NULL,
};

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    phys_addr_t page_addr;
    uintptr_t page_offset;

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

    page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
    page_offset = va & (PAGE_SIZE - 1);
    return page_addr + page_offset;
}

void read_phys_addr(void __user *base, phys_addr_t phys_addr, size_t len)
{
    void *kernel_addr;

    if (!base || !phys_addr || !len)
        return;

    if (!pfn_valid(__phys_to_pfn(phys_addr)))
        return;

    kernel_addr = ioremap_cache(phys_addr, len);
    if (!kernel_addr)
        return;

    copy_to_user(base, kernel_addr, len);
    iounmap(kernel_addr);
}

void write_phys_addr(void __user *base, phys_addr_t phys_addr, size_t len)
{
    void *kernel_addr;

    if (!base || !phys_addr || !len)
        return;

    if (!pfn_valid(__phys_to_pfn(phys_addr)))
        return;

    kernel_addr = ioremap_cache(phys_addr, len);
    if (!kernel_addr)
        return;

    copy_from_user(kernel_addr, base, len);
    iounmap(kernel_addr);
}

static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    struct process_info *info = nlmsg_data(nlh);
    struct mm_struct *mm;
    phys_addr_t pa;

    if (!info)
        return;

    mm = get_mm_by_pid(info->pid);
    if (!mm) {
        pr_err("v2p: get_mm_by_pid failed\n");
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
    pr_info("v2p: module loaded\n");

    cfg.input = nl_recv_msg;
    nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM_PROTOCOL, &cfg);
    if (!nl_sk) {
        pr_err("v2p: netlink create failed\n");
        return -ENOMEM;
    }

    return 0;
}

static void __exit gs_mem_exit(void)
{
    pr_info("v2p: module unloaded\n");
    netlink_kernel_release(nl_sk);
}

module_init(gs_mem_init);
module_exit(gs_mem_exit);
