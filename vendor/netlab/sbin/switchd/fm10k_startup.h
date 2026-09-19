#ifndef NETLAB_FM10K_STARTUP_H
#define NETLAB_FM10K_STARTUP_H
#include <stdbool.h>
#include <stddef.h>
int fm10k_startup_check(const char *profile, char *error, size_t size);
bool fm10k_startup_observe(void);
bool fm10k_startup_validated(void);
bool fm10k_startup_control(void);
bool fm10k_startup_basic100g(void);
#endif
