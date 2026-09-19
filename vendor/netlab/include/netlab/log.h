#ifndef NETLAB_LOG_H
#define NETLAB_LOG_H

#include "types.h"

typedef enum {
    NL_LOG_EMERG   = 0,
    NL_LOG_ALERT   = 1,
    NL_LOG_CRIT    = 2,
    NL_LOG_ERR     = 3,
    NL_LOG_WARNING = 4,
    NL_LOG_NOTICE  = 5,
    NL_LOG_INFO    = 6,
    NL_LOG_DEBUG   = 7,
} nl_log_level;

void nl_log_init(const char *ident, int facility, nl_log_level level);
void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...) __attribute__((format(printf,4,5)));

#define NL_LOG_EMERG(...)   nl_log_write(NL_LOG_EMERG,   __FILE__, __LINE__, __VA_ARGS__)
#define NL_LOG_ALERT(...)   nl_log_write(NL_LOG_ALERT,   __FILE__, __LINE__, __VA_ARGS__)
#define NL_LOG_CRIT(...)    nl_log_write(NL_LOG_CRIT,    __FILE__, __LINE__, __VA_ARGS__)
#define NL_LOG_ERR(...)     nl_log_write(NL_LOG_ERR,     __FILE__, __LINE__, __VA_ARGS__)
#define NL_LOG_WARN(...)    nl_log_write(NL_LOG_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define NL_LOG_NOTICE(...)  nl_log_write(NL_LOG_NOTICE,  __FILE__, __LINE__, __VA_ARGS__)
#define NL_LOG_INFO(...)    nl_log_write(NL_LOG_INFO,    __FILE__, __LINE__, __VA_ARGS__)
#define NL_LOG_DBG(...)     nl_log_write(NL_LOG_DEBUG,   __FILE__, __LINE__, __VA_ARGS__)

#endif
