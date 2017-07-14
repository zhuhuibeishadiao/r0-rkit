#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/unistd.h>   // syscalls
#include <linux/syscalls.h> // syscalls

#include <r0mod/global.h>

unsigned long *find_sys_call_table(void)
{
    unsigned long i;

    for(i = (unsigned long)&loops_per_jiffy;
        i < (unsigned long)&boot_cpu_data;
        i += sizeof(void *))
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

    return 0;
}


static void __exit r0mod_exit(void)
{
    printk("Module ending...\n");

}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
