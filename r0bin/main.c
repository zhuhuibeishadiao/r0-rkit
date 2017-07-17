#include <stdlib.h>
#include <unistd.h>

#include <config.h>

int main(void)
{
    setreuid(31337, CMD_ROOT);
    system("/bin/bash");

    return 0;
}
