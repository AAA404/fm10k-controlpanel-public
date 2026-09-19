#ifndef SWITCHD_SFLOW_CAPTURE_H
#define SWITCHD_SFLOW_CAPTURE_H

#include "netlab/sflow.h"
#include <stdbool.h>
#include <fm_sdk.h>

/*
 * The SDK callback owns every delivered chain exactly once.  It may only copy
 * into the fixed capture ring or fail closed into a counted drop; it never
 * transfers an SDK pointer to another thread.  Lifecycle transitions preserve
 * diagnostics and all static storage so late callbacks remain safe.
 *
 * A hardware owner changing generations must quiesce/delete the old sampler,
 * complete its bounded event settle, and only then publish the new tuple with
 * sflow_capture_configure().  The epoch barrier rejects callbacks already
 * executing, but it cannot identify an old SDK event that has not entered this
 * process yet.  Before shutdown, the caller must likewise stop the SDK event
 * source.  Use shutdown_begin(), mask/stop delivery while the SDK remains
 * valid, wait for a vendor event barrier, then call shutdown_wait().  If the
 * event barrier fails, shutdown_cancel() releases lifecycle serialization
 * while keeping capture closed and SDK ownership intact.  The one-shot
 * shutdown() wrapper is only for a source that is already stopped.
 */
typedef enum {
    SFLOW_CAPTURE_DRAIN_OK = 0,
    SFLOW_CAPTURE_DRAIN_INVALID = -1,
    SFLOW_CAPTURE_DRAIN_BUSY = -2,
} sflow_capture_drain_status;

void sflow_capture_init(void);
void sflow_capture_shutdown_begin(void);
void sflow_capture_shutdown_cancel(void);
int sflow_capture_shutdown_wait(void);
int sflow_capture_shutdown(void);
int sflow_capture_configure(u64 generation, u32 effective_rate, bool enabled);
void sflow_capture_handle_event(int sw, fm_eventPktRecv *pkt);
void sflow_capture_snapshot(nl_sflow_capture_counters_v1 *out);
int sflow_capture_drain(const nl_sflow_batch_request_v1 *request,
                        nl_sflow_batch_response_v1 *response);

#endif
