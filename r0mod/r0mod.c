#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/syscalls.h>

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>

#include <r0mod/global.h>

#define SEARCH_START    PAGE_OFFSET
#define SEARCH_END      ULONG_MAX

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

static int __init r0mod_init(void)
{
    struct page *_sys_call_page;

    printk("Module starting...");

    syscall_table = find_sys_call_table();
    if(syscall_table == NULL)
    {
        printk("syscall_table == NULL");
        return 0;
    }

    _sys_call_page = virt_to_page(&syscall_table);

    return 0;
}


static void __exit r0mod_exit(void)
{
    printk("Module ending...");
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
