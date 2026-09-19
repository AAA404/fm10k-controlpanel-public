#include "netlab/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>

static int g_initialized = 0;
static int g_syslog_facility = LOG_DAEMON;
static nl_log_level g_level = NL_LOG_INFO;

static const char *level_str(nl_log_level lv) {
    switch (lv) {
        case NL_LOG_EMERG:   return "EMERG";
        case NL_LOG_ALERT:   return "ALERT";
        case NL_LOG_CRIT:    return "CRIT";
        case NL_LOG_ERR:     return "ERR";
        case NL_LOG_WARNING: return "WARN";
        case NL_LOG_NOTICE:  return "NOTICE";
        case NL_LOG_INFO:    return "INFO";
        case NL_LOG_DEBUG:   return "DEBUG";
        default:             return "?";
    }
}

static int level_to_syslog(nl_log_level lv) {
    switch (lv) {
        case NL_LOG_EMERG:   return LOG_EMERG;
        case NL_LOG_ALERT:   return LOG_ALERT;
        case NL_LOG_CRIT:    return LOG_CRIT;
        case NL_LOG_ERR:     return LOG_ERR;
        case NL_LOG_WARNING: return LOG_WARNING;
        case NL_LOG_NOTICE:  return LOG_NOTICE;
        case NL_LOG_INFO:    return LOG_INFO;
        case NL_LOG_DEBUG:   return LOG_DEBUG;
        default:             return LOG_INFO;
    }
}

void nl_log_init(const char *ident, int facility, nl_log_level level) {
    g_syslog_facility = facility;
    g_level = level;

    // Environment override: NETLAB_LOG_DEBUG=1 forces DEBUG level
    const char *env = getenv("NETLAB_LOG_DEBUG");
    if (env && env[0] == '1' && env[1] == '\0') {
        g_level = NL_LOG_DEBUG;
    }

    openlog(ident, LOG_PID | LOG_NDELAY, facility);
    g_initialized = 1;
}

void nl_log_write(nl_log_level level, const char *file, int line,
                  const char *fmt, ...) {
    if (!g_initialized) {
        static int once = 0;
        if (!once) {
            once = 1;
            nl_log_init("netlab", LOG_DAEMON, NL_LOG_DEBUG);
        }
    }

    if (level > g_level) return;

    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    syslog(level_to_syslog(level), "%s", msg);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    fprintf(stderr, "%02d:%02d:%02d.%03ld %s %s:%d %s\n",
            tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec / 1000000,
            level_str(level), file, line, msg);
}
