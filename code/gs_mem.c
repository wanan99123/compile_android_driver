#include "gs_mem.h"

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/dcache.h>
#include <linux/rwsem.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/version.h>
#include <linux/string.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define mmap_read_lock(mm)    down_read(&(mm)->mmap_sem)
#define mmap_read_unlock(mm)  up_read(&(mm)->mmap_sem)
#endif

#define ARC_PATH_MAX 256
#define DEVICE_NAME "TearGame"

uintptr_t get_module_base(pid_t pid, char *name)
{
    struct pid *pid_struct;
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    uintptr_t base_addr = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    struct vma_iterator vmi;
#endif

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return 0;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return 0;

    mmap_read_lock(mm);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0))
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma)
#else
    for (vma = mm->mmap; vma; vma = vma->vm_next)
#endif
    {
        if (vma->vm_file) {
            char buf[ARC_PATH_MAX];
            char *path_nm;

            path_nm = d_path(&vma->vm_file->f_path, buf, ARC_PATH_MAX - 1);
            if (!IS_ERR(path_nm)) {
                const char *basename = kbasename(path_nm);
                if (strcmp(basename, name) == 0) {
                    base_addr = vma->vm_start;
                    break;
                }
            }
        }
    }

    mmap_read_unlock(mm);
    mmput(mm);
    return base_addr;
}

bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size)
{
    struct task_struct *task;
    struct pid *pid_struct;
    int bytes_read;
    void *kbuf;

    if (size == 0 || size > (1024 * 1024))
        return false;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return false;

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) {
        put_task_struct(task);
        return false;
    }

    bytes_read = access_process_vm(task, addr, kbuf, size, FOLL_FORCE);
    put_task_struct(task);

    if (bytes_read != size) {
        kfree(kbuf);
        return false;
    }

    if (copy_to_user(buffer, kbuf, size)) {
        kfree(kbuf);
        return false;
    }

    kfree(kbuf);
    return true;
}

bool write_process_memory(pid_t pid, uintptr_t addr, void __user *buffer, size_t size)
{
    struct task_struct *task;
    struct pid *pid_struct;
    int bytes_written;
    void *kbuf;

    if (size == 0 || size > (1024 * 1024))
        return false;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return false;

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) {
        put_task_struct(task);
        return false;
    }

    if (copy_from_user(kbuf, buffer, size)) {
        kfree(kbuf);
        put_task_struct(task);
        return false;
    }

    bytes_written = access_process_vm(task, addr, kbuf, size, FOLL_FORCE | FOLL_WRITE);
    put_task_struct(task);
    kfree(kbuf);

    return (bytes_written == size);
}

static long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    COPY_MEMORY cm;
    MODULE_BASE mb;

    switch (cmd) {
        case OP_READ_MEM: {
            if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
                return -EFAULT;
            return read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
        }

        case OP_WRITE_MEM: {
            if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)))
                return -EFAULT;
            return write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) ? 0 : -EFAULT;
        }

        case OP_MODULE_BASE: {
            if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)))
                return -EFAULT;
            mb.base = get_module_base(mb.pid, mb.name);
            if (copy_to_user((void __user *)arg, &mb, sizeof(mb)))
                return -EFAULT;
            return 0;
        }

        default:
            return -ENOTTY;
    }
}

static int dispatch_open(struct inode *node, struct file *file)
{
    return 0;
}

static int dispatch_close(struct inode *node, struct file *file)
{
    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

static struct miscdevice miscdev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &fops,
};

static int __init gs_mem_init(void)
{
    misc_register(&miscdev);
    printk("gs_mem: loaded\n");
    return 0;
}

static void __exit gs_mem_exit(void)
{
    misc_deregister(&miscdev);
    printk("gs_mem: unloaded\n");
}

module_init(gs_mem_init);
module_exit(gs_mem_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("memory driver");
