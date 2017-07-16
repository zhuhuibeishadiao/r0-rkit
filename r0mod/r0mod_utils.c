#include <r0mod/global.h>

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
