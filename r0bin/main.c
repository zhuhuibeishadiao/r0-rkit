#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    setreuid(1000, 1000);
    system("/bin/sh");
    return 0;
}
