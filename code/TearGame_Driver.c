#include "TearGame_Driver.h"

/* ============================
   内存操作函数实现
   ============================ */

bool read_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct pid *pid_struct;
    int bytes_read;
    void *kbuf;

    if (size == 0 || size > MAX_OPERATION_SIZE)
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

bool write_process_memory(pid_t pid, uintptr_t addr, void *buffer, size_t size)
{
    struct task_struct *task;
    struct pid *pid_struct;
    int bytes_written;
    void *kbuf;

    if (size == 0 || size > MAX_OPERATION_SIZE)
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

/* ============================
   进程信息函数实现
   ============================ */

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

/* ============================
   设备驱动函数实现
   ============================ */

int dispatch_open(struct inode *node, struct file *file)
{
    return 0;
}

int dispatch_close(struct inode *node, struct file *file)
{
    return 0;
}

long dispatch_ioctl(struct file *const file, unsigned int const cmd, unsigned long const arg)
{
    static COPY_MEMORY cm;
    static MODULE_BASE mb;
    static char key[0x100] = {0};
    static char name[0x100] = {0};
    static bool is_verified = false;

    if (cmd == OP_INIT_KEY && !is_verified)
    {
        if (copy_from_user(key, (void __user *)arg, sizeof(key) - 1) != 0)
        {
            return -1;
        }
    }
    
    switch (cmd)
    {
    case OP_READ_MEM:
    {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
        {
            return -1;
        }
        if (read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
        {
            return -1;
        }
        break;
    }
    case OP_WRITE_MEM:
    {
        if (copy_from_user(&cm, (void __user *)arg, sizeof(cm)) != 0)
        {
            return -1;
        }
        if (write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size) == false)
        {
            return -1;
        }
        break;
    }
    case OP_MODULE_BASE:
    {
        if (copy_from_user(&mb, (void __user *)arg, sizeof(mb)) != 0 || 
            copy_from_user(name, (void __user *)mb.name, sizeof(name) - 1) != 0)
        {
            return -1;
        }
        mb.base = get_module_base(mb.pid, name);
        if (copy_to_user((void __user *)arg, &mb, sizeof(mb)) != 0)
        {
            return -1;
        }
        break;
    }
    default:
        break;
    }
    return 0;
}

/* 设备操作结构体 */
struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .release = dispatch_close,
    .unlocked_ioctl = dispatch_ioctl,
};

/* 杂项设备结构体 */
struct miscdevice misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &dispatch_functions,
};

/* 驱动入口函数 */
int __init driver_entry(void)
{
    int ret;

    ret = misc_register(&misc);
    if (ret == 0) {
        printk(KERN_INFO "[TearGame] Device registered: /dev/%s\n", DEVICE_NAME);
        printk(KERN_INFO "[TearGame] Driver loaded successfully!\n");
    } else {
        printk(KERN_ERR "[TearGame] Failed to register device! ret=%d\n", ret);
    }
    return ret;
}

/* 驱动卸载函数 */
void __exit driver_unload(void)
{
    
    misc_deregister(&misc);
    
}

/* 模块初始化和退出声明 */
module_init(driver_entry);
module_exit(driver_unload);

/* 模块信息 */
MODULE_DESCRIPTION("TearGame Memory Driver - t.me/TearGame");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("泪心 QQ:2254013571");
