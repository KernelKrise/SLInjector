#include <dlfcn.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "hooking.h"

unsigned char jmp_hook[] = {0x48, 0x8B, 0x05, 0x02, // mov rax, [rip+2]
                            0x00, 0x00, 0x00, 0xFF, // jmp rax
                            0xE0, 0xEF, 0xBE, 0xAD, // 0xdeadbeef
                            0xDE, 0x00, 0x00, 0x00,
                            0x00};

void *get_page_addr(void *addr)
{
    return (void *)((uintptr_t)addr & ~(uintptr_t)(getpagesize() - 1));
}

int unhook_function(const char *target_function, unsigned char *saved_function_instructions)
{
    // Get original function address
    void *original_function = dlsym(RTLD_NEXT, target_function);

    // Set correct permissions
    if (mprotect(get_page_addr(original_function), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        return -1;
    }

    // Copy the original function back
    memcpy(original_function, saved_function_instructions, sizeof(jmp_hook));

    // Set original permissions
    if (mprotect(get_page_addr(original_function), getpagesize(), PROT_READ | PROT_EXEC) == -1)
    {
        return -1;
    }
    return 0;
}

int hook_function(const char *target_function, void *hook, unsigned char *saved_function_instructions)
{
    // Get original function address
    void *original_function = dlsym(RTLD_NEXT, target_function);

    // Set correct permissions
    if (mprotect(get_page_addr(original_function), getpagesize(), PROT_READ | PROT_WRITE | PROT_EXEC) == -1)
    {
        return -1;
    }

    // Save original function instructions
    memcpy(saved_function_instructions, original_function, sizeof(jmp_hook));

    // Copy the jump hook to the original function
    memcpy(original_function, jmp_hook, sizeof(jmp_hook));

    // Set hook in jmp_hook
    memcpy(original_function + 9, &hook, sizeof(long));

    // Set original permissions
    if (mprotect(get_page_addr(original_function), getpagesize(), PROT_READ | PROT_EXEC) == -1)
    {
        return -1;
    }
    return 0;
}
