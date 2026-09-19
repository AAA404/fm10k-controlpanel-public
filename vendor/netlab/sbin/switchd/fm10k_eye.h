#ifndef NETLAB_FM10K_EYE_H
#define NETLAB_FM10K_EYE_H
#include <stdbool.h>
#include <stddef.h>
int fm10k_eye_command(int sw, const char *command, bool control, char *out, size_t capacity);
void fm10k_eye_poll(int sw);
int fm10k_eye_preempt(int sw);
int fm10k_eye_shutdown(int sw);
/* Scheduler hint only; scan state remains confined to the SDK owner. */
unsigned fm10k_eye_poll_interval_us(void);
#endif
