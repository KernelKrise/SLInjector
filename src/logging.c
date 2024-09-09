#include <stdio.h>
#include <stdarg.h>

#include "logging.h"

// Initialize the default log level
int LOG_LEVEL = LOG_LEVEL_INFO;

int set_log_level(int log_level)
{
    int result = 0;
    switch (log_level)
    {
    case LOG_LEVEL_DEBUG:
        LOG_LEVEL = LOG_LEVEL_DEBUG;
        break;
    case LOG_LEVEL_INFO:
        LOG_LEVEL = LOG_LEVEL_INFO;
        break;
    case LOG_LEVEL_ERROR:
        LOG_LEVEL = LOG_LEVEL_ERROR;
        break;
    case LOG_LEVEL_QUIET:
        LOG_LEVEL = LOG_LEVEL_QUIET;
        break;
    default:
        result = 1;
        break;
    }
    return result;
}

void dlog(const char *format, ...)
{
    if (LOG_LEVEL > LOG_LEVEL_DEBUG)
    {
        return;
    }
    va_list args;
    va_start(args, format);
    printf("[~] ");
    vprintf(format, args);
    va_end(args);
    putchar('\n');
}

void ilog(const char *format, ...)
{
    if (LOG_LEVEL > LOG_LEVEL_INFO)
    {
        return;
    }
    va_list args;
    va_start(args, format);
    printf("[*] ");
    vprintf(format, args);
    va_end(args);
    putchar('\n');
}

void elog(const char *format, ...)
{
    if (LOG_LEVEL > LOG_LEVEL_ERROR)
    {
        return;
    }
    va_list args;
    va_start(args, format);
    printf("[!] ");
    vprintf(format, args);
    va_end(args);
    putchar('\n');
}
