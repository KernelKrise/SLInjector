#include <stdio.h>

__attribute__((constructor)) void library_init(void)
{
    puts("Puts shared library injected!");
}
