#include "fm10k_startup.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int owner_lock = -1;
static bool checked;
static bool basic100g;
static bool control;
bool fm10k_startup_validated(void) { return checked; }
bool fm10k_startup_control(void) { return checked && control; }
bool fm10k_startup_observe(void) { return checked && !control; }
bool fm10k_startup_basic100g(void) { return checked && basic100g; }

int fm10k_startup_check(const char *profile, char *error, size_t size) {
    struct stat metadata;
    const char *observe = getenv("NETLAB_FM10K_OBSERVE_ONLY");
    const char *mode = getenv("NETLAB_FM10K_STARTUP_MODE");
    const char *entry = "/usr/lib/fm10k-controlpanel/entry.py";
    control = mode && !strcmp(mode, "control");
    if (!profile || !observe || strcmp(observe, control ? "0" : "1") || geteuid() != 0) {
        snprintf(error, size, "FM10840 requires an explicitly installed native startup mode");
        return -1;
    }
    if (owner_lock >= 0 || checked) return -1;
    owner_lock = open("/run/lock/fm10k-asic.lock", O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (owner_lock < 0 || fstat(owner_lock, &metadata) || !S_ISREG(metadata.st_mode) ||
        metadata.st_uid || (metadata.st_mode & 0077) || metadata.st_nlink != 1 ||
        flock(owner_lock, LOCK_EX | LOCK_NB)) {
        snprintf(error, size, "FM10840 ASIC ownership lock unavailable");
        return -1;
    }
    /* Retain the lock until process exit, including partial SDK failures. */
    if (lstat(entry, &metadata) || !S_ISREG(metadata.st_mode) || metadata.st_uid || (metadata.st_mode & 0022)) {
        snprintf(error, size, "FM10840 native startup helper is untrusted");
        return -1;
    }
    pid_t child = fork();
    if (child == 0) {
        execl("/usr/bin/python3", "python3", "-I", entry, "native-startup", "--profile", profile, (char *)NULL);
        _exit(127);
    }
    int status = 0;
    pid_t waited;
    do { waited = child > 0 ? waitpid(child, &status, 0) : -1; } while (waited < 0 && errno == EINTR);
    if (waited != child || child <= 0 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        snprintf(error, size, "FM10840 fresh identity/ABI/startup validation failed");
        return -1;
    }
    checked = true;
    basic100g = mode && !strcmp(mode, "basic100g");
    return 0;
}
