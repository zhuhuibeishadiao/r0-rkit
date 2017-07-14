#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/syscalls.h>


#include <r0mod/global.h>

#define SEARCH_START    PAGE_OFFSET
#define SEARCH_END      ULONG_MAX

unsigned long cr0;
unsigned long *syscall_table;

unsigned long *find_sys_call_table(void)
{
    unsigned long i;

    for(i = SEARCH_START; i < SEARCH_END; i += sizeof(void *))
    {
        unsigned long *sys_call_table = (unsigned long *)i;

        if(sys_call_table[__NR_close] == (unsigned long)sys_close)
            return sys_call_table;
    }

    return NULL;
}

static inline void disable_wp(unsigned long cr0)
{
    write_cr0(cr0 & ~0x00010000);
}

static inline void restore_wp(unsigned long cr0)
{
    write_cr0(cr0);
}

static int __init r0mod_init(void)
{
    printk("Module starting...");

    disable_wp(cr0);

    syscall_table = find_sys_call_table();
    if(syscall_table == NULL)
    {
        printk("syscall_table addr = NULL");
        return 1;
    }

    printk("syscall_table addr = %lx", (unsigned long)syscall_table);

    restore_wp(cr0);

    return 0;
}


static void __exit r0mod_exit(void)
{
    printk("Module ending...");


}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
