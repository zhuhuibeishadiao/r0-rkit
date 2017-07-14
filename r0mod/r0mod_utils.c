#include <linux/unistd.h>
#include <linux/syscalls.h>

#include <r0mod/global.h>
#include <r0mod/hooks.h>
#include <r0mod/utils.h>

unsigned long **sct;

unsigned long **locate_sct(void)
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

void disable_page_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if(!(value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

void enable_page_protection(void)
{
    unsigned long value;
    asm volatile("mov %%cr0, %0" : "=r" (value));

    if((value & 0x00010000))
        return;

    asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}
