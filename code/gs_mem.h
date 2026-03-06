#ifndef GS_MEM_H
#define GS_MEM_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/mmzone.h>

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

// 外部声明
extern struct sock *nl_sk;
extern struct netlink_kernel_cfg cfg;
extern struct process_info *process_info_data;

#endif // GS_MEM_H
