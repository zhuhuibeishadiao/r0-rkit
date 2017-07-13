#ifndef _R0MOD_STRUCTS_H
#   define _R0MOD_STRUCTS_H

// Copied from 'fs/readdir.h'
struct linux_dirent
{
    unsigned long   d_ino;
    unsigned long   d_off;
    unsigned short  d_reclen;
    char            d_name[1];
};

#endif
