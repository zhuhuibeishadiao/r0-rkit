#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

#include <r0mod/global.h>

static int __init r0mod_init(void)
{
    fm_alert("%s\n", "R0Mod: Initialized.");

    return 0;
}


static void __exit r0mod_exit(void)
{
    fm_alert("%s\n", "R0Mod: Uninitialized.");

    return;
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
