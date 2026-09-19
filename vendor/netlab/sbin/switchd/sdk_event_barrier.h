#ifndef SWITCHD_SDK_EVENT_BARRIER_H
#define SWITCHD_SDK_EVENT_BARRIER_H

#include <stdbool.h>

/*
 * The pinned FM10840 SDK has one global event dispatcher and one local
 * process dispatcher.  A software-event sentinel crosses both FIFO queues,
 * which makes its acknowledgement a real barrier for callbacks selected by
 * an older process-event mask.
 */
void sdk_event_barrier_init(void);
bool sdk_event_barrier_handle(int event, void *event_info);
int sdk_event_barrier_drain(int sw, bool switch_up);
int sdk_event_barrier_stop(void);

#endif
