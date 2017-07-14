#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/unistd.h>
#include <linux/syscalls.h>

unsigned long **sct;

static unsigned long **aquire_sct(void)
{
    unsigned long int offset = PAGE_OFFSET;
    unsigned long **sct;

    while(offset < ULLONG_MAX)
    {
        sct = (unsigned long **)offset;
        if(sct[__NR_close] == (unsigned long *)sys_close)
        {
            printk(KERN_INFO "Succeeded to get sys_call_table!\n");
            return sct;
        }

        offset += sizeof(void *);
    }

    printk(KERN_WARN "Failed to get sys_call_table!\n");

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
    printk(KERN_INFO "Module starting...\n");

    if(!(sct = aquire_sct()))
    {
        return -1;
    }

    printk(KERN_INFO "sct: %lx\n", (unsigned long)sct);

    return 0;
}

static void __exit r0mod_exit(void)
{
    printk(KERN_INFO "Module ending...\n");
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
