#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    setreuid(1337, 0);
    system("/bin/bash");

    return 0;
}
