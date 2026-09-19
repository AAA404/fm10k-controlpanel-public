#ifndef NETLAB_EVENT_H
#define NETLAB_EVENT_H

#include "types.h"

typedef struct {
    u64     publisher_id;
    u64     epoch;
    u64     sequence;
    char    topic[64];
    u32     payload_len;
    u8      payload[];
} nl_event;

typedef void (*nl_event_callback)(nl_event *evt, void *userdata);

typedef struct nl_event_bus nl_event_bus;

nl_event_bus *nl_eventbus_create(u64 publisher_id, u64 epoch);
void          nl_eventbus_destroy(nl_event_bus *bus);

u64 nl_eventbus_next_seq(nl_event_bus *bus);

nl_status nl_eventbus_publish(nl_event_bus *bus, const char *topic,
                              void *data, u32 len);

nl_status nl_eventbus_subscribe(nl_event_bus *bus, const char *topic,
                                nl_event_callback cb, void *userdata);

nl_status nl_eventbus_unsubscribe(nl_event_bus *bus, const char *topic,
                                  nl_event_callback cb);

// For gap detection
typedef struct {
    u64 publisher_id;
    u64 epoch;
    u64 last_sequence;
} nl_event_stream_state;

nl_status nl_eventbus_get_snapshot(nl_event_bus *bus,
                                   nl_event_stream_state *state);

#endif
