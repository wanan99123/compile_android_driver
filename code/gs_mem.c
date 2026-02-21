#include "gs_mem.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jayne");
MODULE_DESCRIPTION("一个通过Netlink调用内核模块实现内核级物理内存读取的简单示例");
MODULE_VERSION("0.1");


// 接收Netlink消息的回调函数
static void nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    int pid;
    int send_pid;
    size_t virt_addr;
    phys_addr_t phys_addr;
    void* kernel_addr = NULL;
    size_t len;
    struct mm_struct *mm;
    void *base;
    int type;
    char kernel_module_name[MAX_ADDR_LEN];
    uintptr_t ptr;
	ssize_t ret;

    //printk(KERN_INFO "v2p: Entering: %s\n", __FUNCTION__);

    nlh = (struct nlmsghdr *)skb->data;

    send_pid = nlh->nlmsg_pid; // 发送方进程的PID

    // 解析虚拟地址和偏移量
    process_info_data = (struct process_info *)nlmsg_data(nlh);

    pid = process_info_data->pid;
    len = process_info_data->len;
    base = process_info_data->base;
    type = process_info_data->type;

    //printk(KERN_ERR "v2p: send pid: %d,pid: %d,virt_addr: %lx,len: %ld\n",send_pid,pid,virt_addr,len);

    mm = get_mm_by_pid(pid);

    if (!mm) {
        printk(KERN_ERR "v2p: 获取mm 出错\n");
        return;
    }
    mmput(mm);

    if(type == 2){
        ret = copy_from_user(kernel_module_name, process_info_data->module_name, 
                sizeof(kernel_module_name));
        ptr = get_module_base(mm,kernel_module_name);
        printk(KERN_INFO "v2p name: %s,ptr: %lx\n",kernel_module_name,ptr);
        ret = copy_to_user(base, &ptr, len);
        return;
    }

    virt_addr = process_info_data->virt_addr;

    phys_addr = translate_linear_address(mm,virt_addr);

    if(type == 0){
        read_phys_addr(base,phys_addr,kernel_addr,len);
    }else if(type == 1){
        write_phys_addr(base,phys_addr,kernel_addr,len);
    }
}

// 模块初始化函数
static int __init netlink_virt_to_phys_init(void) {
    //struct module *mod;

    printk(KERN_INFO "v2p: Loading netlink_virt_to_phys module...\n");

    cfg.input = nl_recv_msg;

    nl_sk = netlink_kernel_create(&init_net, NETLINK_CUSTOM_PROTOCOL, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "v2p: Error creating socket.\n");
        return -10;
    }

    // 隐藏模块
    // mod = THIS_MODULE;
    // list_del_init(&mod->list);
    // kobject_del(&mod->mkobj.kobj);
    // mod->sect_attrs = NULL;
    // mod->notes_attrs = NULL;

    return 0;
}

// 模块卸载函数
static void __exit netlink_virt_to_phys_exit(void) {
    printk(KERN_INFO "v2p: Unloading netlink_virt_to_phys module...\n");

    netlink_kernel_release(nl_sk);
}

module_init(netlink_virt_to_phys_init);
module_exit(netlink_virt_to_phys_exit);