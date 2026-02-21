#ifndef GS_MEM_H
#define GS_MEM_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/netlink.h>
#include <asm/io.h>
#include <linux/highmem.h>
#include <linux/uaccess.h>
#include <linux/string.h>

#define MAX_ADDR_LEN        128
#define NETLINK_CUSTOM_PROTOCOL 20

struct process_info {
    pid_t               pid;
    size_t              virt_addr;
    size_t              len;
    void __user         *base;
    int                 type;
    char                module_name[MAX_ADDR_LEN];
};

#endif
