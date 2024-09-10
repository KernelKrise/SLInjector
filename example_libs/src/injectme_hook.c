#include <stdio.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "hooking.h"

unsigned char putc_saved_body[JMP_HOOK_SIZE];

int hook(int c, FILE *stream)
{
    unhook_function("putc", putc_saved_body);

    printf("Hooked putc(0x%x, %p)\n", c, stream);
    int result = putc(c, stream);
    printf("\nResult: %d\n", result);

    hook_function("putc", hook, putc_saved_body);
    return result;
}

__attribute__((constructor)) void library_init(void)
{
    puts("Hooking putc...");
    hook_function("putc", hook, putc_saved_body);
}
