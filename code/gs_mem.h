#ifndef GS_MEM_H
#define GS_MEM_H

#include <linux/types.h>

#define NETLINK_CUSTOM_PROTOCOL 20
#define MAX_ADDR_LEN 256

struct process_info {
    pid_t pid;
    size_t virt_addr;
    size_t len;
    void *base;
    int type;
    char module_name[MAX_ADDR_LEN];
};

#endif // GS_MEM_H
