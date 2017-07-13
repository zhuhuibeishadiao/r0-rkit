#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/mutex.h>
#include <linux/syscalls.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#include <r0mod/global.h>

void **sys_call_table;

asmlinkage long _hook_sys_openat(unsigned int dfd,
    const char __user *filename, int flags, umode_t mode)
{
    printk("into openat syscall hook");
    return real_sys_openat(dfd,filename,flags,mode);
}

// find sys_call_table through sys_close address
static unsigned long **find_sys_call_table(void)
{
    unsigned long offset;
    unsigned long **sct;

    int flag = 0;

    //sys call num maybe different
    //check in unistd.h
    //__NR_close will use 64bit version unistd.h by default when build LKM
    for(offset = PAGE_OFFSET; offset < ULLONG_MAX; offset += sizeof(void *))
    {
        sct = (unsigned long **)offset;
        if(sct[__NR_close] == (unsigned long *)sys_close)
        {
            if(flag == 0)
            {
                printk("Found sys_call_table @ %llx", (long long unsigned int)sct);
                return sct;
            }
            else
            {
                printk("Found first sys_call_table @ %llx", (long long unsigned int)sct);
                flag--;
            }
        }
    }

    /*
     * Given the loop limit, it's somewhat unlikely we'll get here. I don't
     * even know if we can attempt to fetch such high addresses from memory,
     * and even if you can, it will take a while!
     */
    return NULL;
}



static int __init r0mod_init(void)
{
    printk("Module starting...");

    sys_call_table = (void*)find_sys_call_table();
    printk("Found sys_call_table @ %llx", (long long unsigned int)sys_call_table);

    real_sys_openat = (void*)(sys_call_table[__NR_openat]);
    printk("real_openat addr @ %llx", (long long unsigned int)real_sys_openat);
    printk("_NR_openat:%d", __NR_openat);
    printk("hook_openat addr @ %llx", (long long unsigned int)_hook_sys_openat);

    sys_call_table[__NR_openat] = &_hook_sys_openat;

    return 0;
}


static void __exit r0mod_exit(void)
{
    printk("Module ending...");

    sys_call_table[__NR_openat] = real_sys_openat;

    return;
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
