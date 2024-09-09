#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <stdio.h>

#include "logging.h"
#include "banner.h"
#include "slinjector.h"

int main(int argc, char **argv)
{
    pid_t target_pid;
    char *target_pid_endptr;
    char *target_lib;

    // Set log level
    if (set_log_level(LOG_LEVEL_DEBUG))
    {
        elog("Logging configuration error");
        return EXIT_FAILURE;
    }

    // Print banner
    puts(BANNER);

    // Parse arguments
    if (argc != 3)
    {
        elog("Usage: %s <pid> <path_to_lib>\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Parse target pid argument
    errno = 0;
    target_pid = strtoul(argv[1], &target_pid_endptr, 10);
    if (errno == ERANGE ||
        target_pid > (unsigned long)INT_MAX ||
        target_pid_endptr == argv[1] ||
        *target_pid_endptr != '\0')
    {
        elog("Error parsing target pid");
        return EXIT_FAILURE;
    }
    dlog("TARGET PID: %d", target_pid);

    // Parse target lib argument
    target_lib = argv[2];
    if (access(target_lib, R_OK | X_OK) != 0)
    {
        elog("File '%s' not found or don't have read and execute permissions", target_lib);
        return EXIT_FAILURE;
    }
    dlog("TARGET LIB: %s", target_lib);

    ilog("Starting process injection...");
    if (inject_library(target_pid, target_lib) == -1)
    {
        elog("Process injection failed");
        return EXIT_FAILURE;
    }
    ilog("Process injection successful");

    return EXIT_SUCCESS;
}
