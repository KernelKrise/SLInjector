#ifndef LOGGING_H
#define LOGGING_H

extern int LOG_LEVEL;

#define LOG_LEVEL_DEBUG 1
#define LOG_LEVEL_INFO 2
#define LOG_LEVEL_ERROR 3
#define LOG_LEVEL_QUIET 4

int set_log_level(int log_level);

void dlog(const char *format, ...);
void ilog(const char *format, ...);
void elog(const char *format, ...);

#endif // LOGGING_H
