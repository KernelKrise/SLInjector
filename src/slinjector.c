#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dlfcn.h>

#include "logging.h"

#define CALLING_SHELLCODE_OFFSET 12 // Offset to center of nop sled

unsigned char syscall_shellcode[] = {0x0F, 0x05};

unsigned char call_shellcode[] = {0xEF, 0xBE, 0xAD, 0xDE, // call_shellcode =
                                  0x00, 0x00, 0x00, 0x00, // p64(0xdeadbeef) +
                                  0x90, 0x90, 0x90, 0x90, // asm("nop") * 7 +
                                  0x90, 0x90, 0x90, 0x48, // asm("mov rax, [rip-22]") +
                                  0x8B, 0x05, 0xEA, 0xFF, // asm("jmp rax")
                                  0xFF, 0xFF, 0xFF, 0xE0};

int remote_write_data(pid_t pid, void *addr, const void *data, size_t size)
{
    // Write data to the target process's memory
    const char *data_ptr = data;
    size_t written = 0;
    while (written < size)
    {
        // Calculate the size of the data to write in one go
        size_t chunk_size = sizeof(long);
        if (size - written < chunk_size)
        {
            chunk_size = size - written;
        }

        // Read current memory content to preserve the rest
        long old_data = ptrace(PTRACE_PEEKDATA, pid, addr + written, NULL);
        if (old_data == -1 && errno != 0)
        {
            elog("PTRACE_PEEKDATA error: %s", strerror(errno));
            return -1;
        }

        // Create a mask for the data to write
        long new_data = old_data;
        memcpy(&new_data, data_ptr, chunk_size);

        // Write new data to the target process's memory
        if (ptrace(PTRACE_POKEDATA, pid, addr + written, new_data) == -1)
        {
            elog("PTRACE_POKEDATA error: %s", strerror(errno));
            return -1;
        }

        data_ptr += chunk_size;
        written += chunk_size;
    }
}

unsigned long inject_calling_shellcode(pid_t pid)
{
    // Attach to process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        elog("PTRACE_ATTACH error: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    waitpid(pid, NULL, 0);
    dlog("Successfully attached to process");

    // Save registers
    struct user_regs_struct regs;
    struct user_regs_struct saved_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        elog("PTRACE_GETREGS error: %s", strerror(errno));
        return -1;
    }
    memcpy(&saved_regs, &regs, sizeof(regs));
    dlog("Registers saved");

    // Backup the current instruction pointer
    unsigned long backup_instructions = ptrace(PTRACE_PEEKTEXT, pid, (void *)regs.rip, NULL);
    dlog("Instructions backed up");

    // Write syscall shellcode to rip address
    remote_write_data(pid, (void *)saved_regs.rip, syscall_shellcode, sizeof(syscall_shellcode));
    dlog("Syscall shellcode written");

    // Set registers to invoke mmap syscall
    regs.rax = 0x9;  // mmap syscall number
    regs.rdi = 0;    // addr
    regs.rsi = 4096; // length
    regs.rdx = 5;    /* PROT_READ | PROT_EXEC */
    regs.r10 = 0x22; /* MAP_PRIVATE | MAP_ANONYMOUS */
    regs.r8 = -1;    // fd
    regs.r9 = 0;     // offset

    // Set the new registers state
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
        elog("PTRACE_SETREGS error: %s", strerror(errno));
        return -1;
    }
    dlog("Registers set");

    // Invoke mmap syscall
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1)
    {
        elog("PTRACE_SINGLESTEP error: %s", strerror(errno));
        return -1;
    }
    waitpid(pid, NULL, 0);
    dlog("Syscall invoked");

    // Get the current registers state
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        elog("PTRACE_GETREGS error: %s", strerror(errno));
        return -1;
    }
    dlog("Return value: 0x%lx", regs.rax);

    // Restore the saved registers state
    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1)
    {
        elog("PTRACE_SETREGS error: %s", strerror(errno));
        return -1;
    }
    dlog("Registers restored");

    // Restore the original instructions
    remote_write_data(pid, (void *)saved_regs.rip, &backup_instructions, sizeof(backup_instructions));
    dlog("Instructions restored");

    // Write the shellcode to the allocated memory
    remote_write_data(pid, (void *)regs.rax, call_shellcode, sizeof(call_shellcode));
    dlog("Shellcode written");

    // Detach from process
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
    {
        elog("PTRACE_DETACH error: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    dlog("Successfully detached from process");

    return regs.rax;
}

unsigned long get_library_base_address(pid_t pid, const char *lib_name)
{
    // Get the maps file path
    char maps_path[0x100];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    // Open the maps file
    FILE *maps_file = fopen(maps_path, "r");
    if (maps_file == NULL)
    {
        elog("fopen(%s) error: %s", maps_path, strerror(errno));
        return 0;
    }

    // Search for the library base address
    unsigned long base_address = 0;
    char line[4096];
    while (fgets(line, sizeof(line), maps_file) != NULL)
    {
        if (strstr(line, lib_name) != NULL)
        {
            char *base_address_str = strtok(line, "-");
            base_address = strtol(base_address_str, NULL, 16);
            break;
        }
    }

    // Close the maps file
    fclose(maps_file);

    return base_address;
}

long call_remote_function(pid_t pid, void *function_address, long *args, size_t argc, unsigned long calling_shellcode_address)
{
    // Attach to process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
    {
        elog("PTRACE_ATTACH error: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    waitpid(pid, NULL, 0);
    dlog("Successfully attached to process");

    // Save the current registers state
    struct user_regs_struct regs;
    struct user_regs_struct saved_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        elog("PTRACE_GETREGS error: %s", strerror(errno));
        return -1;
    }
    memcpy(&saved_regs, &regs, sizeof(regs));
    dlog("Registers saved");

    // Set first 6 function arguments / amd64 / linux
    for (size_t i = 0; i < argc && i < 6; i++)
    {
        switch (i)
        {
        case 0:
            regs.rdi = args[i];
            break;
        case 1:
            regs.rsi = args[i];
            break;
        case 2:
            regs.rdx = args[i];
            break;
        case 3:
            regs.rcx = args[i];
            break;
        case 4:
            regs.r8 = args[i];
            break;
        case 5:
            regs.r9 = args[i];
            break;
        }
    }

    // Substrack from rsp to make stack aligned
    regs.rsp -= sizeof(long);

    // Set args if more than 6
    if (argc > 6)
    {
        if ((argc - 6) % 2 != 0)
            regs.rsp -= (argc - 6) * sizeof(long);
        else
            regs.rsp -= (argc - 6) * sizeof(long) + sizeof(long);
        remote_write_data(pid, (void *)regs.rsp, args + 6, (argc - 6) * sizeof(long));
    }
    dlog("Arguments set");

    // Set return address to 0 to catch the function return
    regs.rsp -= sizeof(long);
    unsigned long return_address = 0;
    remote_write_data(pid, (void *)regs.rsp, &return_address, sizeof(long));
    dlog("Return address set");

    // Write function pointer to calling shellcode
    remote_write_data(pid, (void *)calling_shellcode_address, &function_address, sizeof(long));
    dlog("Function address written");

    // Set the instruction pointer to the calling shellcode address
    regs.rip = (unsigned long)calling_shellcode_address + CALLING_SHELLCODE_OFFSET;
    dlog("Instruction pointer set");

    // Set the new registers state
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    {
        elog("PTRACE_SETREGS error: %s", strerror(errno));
        return -1;
    }
    dlog("Registers set");

    // Continue the process
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1)
    {
        elog("PTRACE_CONT error: %s", strerror(errno));
        return -1;
    }
    dlog("Continuing process");

    // Wait for the process to stop
    waitpid(pid, NULL, WUNTRACED);
    dlog("Process stopped");

    // Get the current registers state
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    {
        elog("PTRACE_GETREGS error: %s", strerror(errno));
        return -1;
    }
    dlog("Return value: 0x%lx", regs.rax);

    // Restore the saved registers state
    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1)
    {
        elog("PTRACE_SETREGS error: %s", strerror(errno));
        return -1;
    }
    dlog("Registers restored");

    // Detach from process
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
    {
        elog("PTRACE_DETACH error: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    dlog("Successfully detached from process");

    return regs.rax;
}

int inject_library(pid_t pid, char *lib_path)
{
    ilog("Injecting library '%s' into process %d", lib_path, pid);

    // Get calling primitive address
    unsigned long calling_shellcode_address = inject_calling_shellcode(pid);
    if (calling_shellcode_address == 0)
    {
        elog("Failed to inject calling shellcode into process %d", pid);
        return -1;
    }
    ilog("Calling shellcode injected at address: 0x%lx", calling_shellcode_address);

    // Get the remote libc base address
    unsigned long remote_libc_base_address = get_library_base_address(pid, "libc.so.6");
    if (remote_libc_base_address == 0)
    {
        elog("Cant find remote libc base address for process %d", pid);
        return -1;
    }
    ilog("Remote libc base address: 0x%lx", remote_libc_base_address);

    // Get the local libc base address
    unsigned long local_libc_base_address = get_library_base_address(getpid(), "libc.so.6");
    if (local_libc_base_address == 0)
    {
        elog("Cant find local libc base address");
        return -1;
    }
    ilog("Local libc base address: 0x%lx", local_libc_base_address);

    // Calculate the offset between the local and remote libc base addresses
    long libc_base_address_diff = remote_libc_base_address - local_libc_base_address;
    dlog("libc base address diff: 0x%lx", libc_base_address_diff);

    // Write the library path to the target process's memory
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) // Attach to process
    {
        elog("PTRACE_ATTACH error: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    waitpid(pid, NULL, 0);
    dlog("Successfully attached to process");

    unsigned long lib_path_remote_address = calling_shellcode_address + 0x100;
    if (remote_write_data(pid, (void *)lib_path_remote_address, lib_path, strlen(lib_path) + 1) == -1)
    {
        elog("Failed to write library path to target process");
        return -1;
    }
    ilog("Library path written to 0x%lx", lib_path_remote_address);

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) // Detach from process
    {
        elog("PTRACE_DETACH error: %s", strerror(errno));
        return EXIT_FAILURE;
    }
    dlog("Successfully detached from process");

    // Call dlopen function in the target process
    unsigned long dlopen_remote_address = libc_base_address_diff + (unsigned long)dlopen;
    ilog("Calling dlopen at address: 0x%lx", dlopen_remote_address);
    long dlopen_args[] = {lib_path_remote_address, RTLD_LAZY};
    long dlopen_result = call_remote_function(
        pid,
        (void *)dlopen_remote_address,
        dlopen_args,
        2,
        calling_shellcode_address);
    ilog("dlopen result: 0x%lx", dlopen_result);

    if (dlopen_result == 0)
    {
        elog("Failed to load library '%s' into process %d", lib_path, pid);
        return -1;
    }

    return 0;
}
