#ifndef _TEARGAME_DRIVER_H_
#define _TEARGAME_DRIVER_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/tty.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/rwsem.h>

/* 项目信息 */
#define DEVICE_NAME "TearGame"
#define ARC_PATH_MAX 256
#define MAX_OPERATION_SIZE (1024 * 1024) /* 最大1MB操作 */

/* 内核版本兼容处理 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define mmap_read_lock(mm)    down_read(&(mm)->mmap_sem)
#define mmap_read_unlock(mm)  up_read(&(mm)->mmap_sem)
#endif

/* 数据结构定义 */
typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void *buffer;
    size_t size;
} COPY_MEMORY, *PCOPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char *name;
    uintptr_t base;
} MODULE_BASE, *PMODULE_BASE;

/* 操作命令枚举 */
enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
};

/* 函数声明 */
/* 内存操作函数 */
bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);
bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size);

/* 进程信息函数 */
uintptr_t get_module_base(pid_t pid, char *name);

/* 设备驱动函数 */
int dispatch_open(struct inode *node, struct file *file);
int dispatch_close(struct inode *node, struct file *file);
long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg);
int __init driver_entry(void);
void __exit driver_unload(void);

#endif /* _TEARGAME_DRIVER_H_ */
