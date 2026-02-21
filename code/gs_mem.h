#ifndef __GS_MEM_H__
#define __GS_MEM_H__

#include <linux/types.h>

#define NETLINK_CUSTOM_PROTOCOL 20
#define GS_MEM_MAX_ADDR_LEN 256

struct process_info {
    pid_t pid;
    size_t virt_addr;
    size_t len;
    void *base;
    int type;
    char module_name[GS_MEM_MAX_ADDR_LEN];
};

#endif
