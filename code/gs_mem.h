#ifndef __GS_MEM_H__
#define __GS_MEM_H__

#include <linux/types.h>
#include <linux/pid.h>

typedef struct _COPY_MEMORY {
    pid_t pid;
    uintptr_t addr;
    void __user *buffer;
    size_t size;
} COPY_MEMORY;

typedef struct _MODULE_BASE {
    pid_t pid;
    char name[256];
    uintptr_t base;
} MODULE_BASE;

enum OPERATIONS {
    OP_INIT_KEY = 0x800,
    OP_READ_MEM = 0x801,
    OP_WRITE_MEM = 0x802,
    OP_MODULE_BASE = 0x803,
};

#endif
