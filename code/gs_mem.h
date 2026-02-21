#ifndef GS_MEM_H
#define GS_MEM_H

#include <linux/module.h>
#include <linux/types.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/netlink.h>
#include <linux/net_namespace.h>
#include <asm/io.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define MAX_ADDR_LEN 128

struct process_info {
    pid_t pid;
    size_t virt_addr;
    size_t len;
    void __user *base;
    int type; // 0=读物理 1=写物理
};

extern struct sock *nl_sk;
extern struct netlink_kernel_cfg cfg;

static inline struct mm_struct *get_mm_by_pid(pid_t nr)
{
    struct task_struct *task;
    rcu_read_lock();
    task = pid_task(find_vpid(nr), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return NULL;
    }
    struct mm_struct *mm = get_task_mm(task);
    rcu_read_unlock();
    return mm;
}

phys_addr_t translate_linear_address(struct mm_struct *mm, uintptr_t va);
void read_phys_addr(void __user *base, phys_addr_t phys_addr, size_t len);
void write_phys_addr(void __user *base, phys_addr_t phys_addr, size_t len);

#endif
