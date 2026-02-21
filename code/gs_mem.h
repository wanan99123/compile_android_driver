#include <linux/init.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <net/sock.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/sched/mm.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/highmem.h>

#define NETLINK_CUSTOM_PROTOCOL 20
#define ARC_PATH_MAX 256

struct process_info {
    pid_t pid; // 进程ID
    size_t virt_addr; // 虚拟地址
    size_t len; // 数据长度
    void *base;
    int type;
    char *module_name;
};

struct sock *nl_sk = NULL; // Netlink套接字
struct netlink_kernel_cfg cfg; // Netlink内核配置
struct process_info *process_info_data; // 进程信息数据

static inline struct mm_struct *get_mm_by_pid(pid_t nr);
// 根据进程ID获取进程的内存管理结构体
static inline struct mm_struct *get_mm_by_pid(pid_t nr)
{
    struct task_struct *task;

    task = pid_task(find_vpid(nr), PIDTYPE_PID);
    if (!task)
        return NULL;

    return get_task_mm(task);
}

uintptr_t get_module_base(struct mm_struct* mm, char* name);

uintptr_t get_module_base(struct mm_struct* mm, char* name) 
{
    struct vm_area_struct *vma;

    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        char buf[ARC_PATH_MAX];
        char *path_nm = "";

        if (vma->vm_file) {
            path_nm = file_path(vma->vm_file, buf, ARC_PATH_MAX-1);
            if (!strcmp(kbasename(path_nm), name)) {
                return vma->vm_start;
            }
        }
    }
    return 0;
}

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va);

phys_addr_t translate_linear_address(struct mm_struct* mm, uintptr_t va) {

    pgd_t *pgd;
    p4d_t *p4d;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
	
    phys_addr_t page_addr;
    uintptr_t page_offset;
    
    pgd = pgd_offset(mm, va);
    if(pgd_none(*pgd) || pgd_bad(*pgd)) {
        return 0;
    }
    p4d = p4d_offset(pgd, va);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) {
    	return 0;
    }
	pud = pud_offset(p4d,va);
	if(pud_none(*pud) || pud_bad(*pud)) {
        return 0;
    }
	pmd = pmd_offset(pud,va);
	if(pmd_none(*pmd)) {
        return 0;
    }
	pte = pte_offset_kernel(pmd,va);
	if(pte_none(*pte)) {
        return 0;
    }
	if(!pte_present(*pte)) {
        return 0;
    }
	//页物理地址
	page_addr = (phys_addr_t)(pte_pfn(*pte) << PAGE_SHIFT);
	//页内偏移
	page_offset = va & (PAGE_SIZE-1);
	
	return page_addr + page_offset;
}

void read_phys_addr(void *base,phys_addr_t phys_addr,void* kernel_addr,size_t len);
void read_phys_addr(void *base,phys_addr_t phys_addr,void* kernel_addr,size_t len){
    if (!phys_addr) {
        printk(KERN_ERR "v2p: read_phys_addr获取phys_addr 出错\n");
        return;
    }

    if (!pfn_valid(__phys_to_pfn(phys_addr))) {
        return;
    }
    kernel_addr = ioremap_cache(phys_addr, len);

    if(!kernel_addr){
        printk(KERN_ERR "v2p: read_phys_addr获取 kernel_addr 出错\n");
        return;
    }
    
    if(copy_to_user(base, kernel_addr, len)) {
        iounmap(kernel_addr);
        return;
    }
    iounmap(kernel_addr);
}

void write_phys_addr(void *base,phys_addr_t phys_addr,void* kernel_addr,size_t len);
void write_phys_addr(void *base,phys_addr_t phys_addr,void* kernel_addr,size_t len){
    if (!phys_addr) {
        printk(KERN_ERR "v2p: write_phys_addr获取phys_addr 出错\n");
        return;
    }

    if (!pfn_valid(__phys_to_pfn(phys_addr))) {
        return;
    }
    kernel_addr = ioremap_cache(phys_addr, len);

    if(!kernel_addr){
        printk(KERN_ERR "v2p: write_phys_addr获取 kernel_addr 出错\n");
        return;
    }
    
    if(copy_from_user(kernel_addr, base, len)) {
        iounmap(kernel_addr);
        return;
    }
    iounmap(kernel_addr);
}