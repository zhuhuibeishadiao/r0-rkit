#include <r0mod/global.h>

#if defined(__i386__)
#   define HIJACK_SIZE 6
#else
#   define HIJACK_SIZE 12
#endif

struct sym_hook
{
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
    struct list_head list;
};

LIST_HEAD(hooked_syms);

void hook_start(void *target, void *new)
{
    unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];

    struct sym_hook *sa;

#if defined(__i386__)
    // push $addr; ret
    memcpy(n_code, "\x68\x00\x00\x00\x00\xc3", HIJACK_SIZE);
    *(unsigned long *)&n_code[1] = (unsigned long)new;
#else
    // mov rax, $addr; jmp rax
    memcpy(n_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", HIJACK_SIZE);
    *(unsigned long *)&n_code[2] = (unsigned long)new;
#endif

    DEBUG_HOOK("Hooking function 0x%p with 0x%p\n", target, new);

    memcpy(o_code, target, HIJACK_SIZE);

    write_cr0(read_cr0() & (~0x10000));
    memcpy(target, n_code, HIJACK_SIZE);
    write_cr0(read_cr0() | 0x10000);

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if(!sa)
        return;

    sa->addr = target;
    memcpy(sa->o_code, o_code, HIJACK_SIZE);
    memcpy(sa->n_code, n_code, HIJACK_SIZE);

    list_add(&sa->list, &hooked_syms);
}

void hook_pause(void *target)
{
    struct sym_hook *sa;

    DEBUG_HOOK("Pausing hook of function 0x%p\n", target);

    list_for_each_entry(sa, &hooked_syms, list)
    {
        if(target == sa->addr)
        {
            write_cr0(read_cr0() & (~0x10000));
            memcpy(target, sa->o_code, HIJACK_SIZE);
            write_cr0(read_cr0() | 0x10000);
        }
    }
}

void hook_resume(void *target)
{
    struct sym_hook *sa;

    DEBUG_HOOK("Resuming hook of function 0x%p\n", target);

    list_for_each_entry(sa, &hooked_syms, list)
    {
        if(target == sa->addr)
        {
            write_cr0(read_cr0() & (~0x10000));
            memcpy(target, sa->n_code, HIJACK_SIZE);
            write_cr0(read_cr0() | 0x10000);
        }
    }
}

void hook_stop(void *target)
{
    struct sym_hook *sa;

    DEBUG_HOOK("Unhooking function 0x%p\n", target);

    list_for_each_entry(sa, &hooked_syms, list)
    {
        if(target == sa->addr)
        {
            write_cr0(read_cr0() & (~0x10000));
            memcpy(target, sa->o_code, HIJACK_SIZE);
            write_cr0(read_cr0() | 0x10000);
            list_del(&sa->list);
            kfree(sa);
            break;
        }
    }
}

char *strnstr(const char *haystack, const char *needle, size_t n)
{
    char *s = strstr(haystack, needle);

    if(s == NULL)
        return NULL;

    if(s - haystack + strlen(needle) <= n)
        return s;
    else
        return NULL;
}

void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size)
{
    char *p;

    for (p = (char *)haystack; p <= ((char *)haystack - needle_size + haystack_size); p++)
        if(memcmp(p, needle, needle_size) == 0)
            return (void *)p;

    return NULL;
}

void *memstr(const void *haystack, const char *needle, size_t size)
{
    size_t needle_size = strlen(needle);
    char *p;

    for(p = (char *)haystack; p <= ((char *)haystack - needle_size + size); p++)
    {
        if(memcmp(p, needle, needle_size) == 0)
            return (void *)p;
    }

    return NULL;
}

MODULE_LICENSE("GPL");
