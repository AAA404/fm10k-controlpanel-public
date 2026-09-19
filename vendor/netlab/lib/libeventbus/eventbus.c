#include "netlab/event.h"
#include "netlab/log.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_SUBSCRIBERS 64

typedef struct subscriber {
    char topic[64];
    nl_event_callback cb;
    void *userdata;
    struct subscriber *next;
} subscriber_t;

struct nl_event_bus {
    u64 publisher_id;
    u64 epoch;
    u64 sequence;
    subscriber_t *subscribers;
    int num_subscribers;
    pthread_mutex_t lock;
};

nl_event_bus *nl_eventbus_create(u64 publisher_id, u64 epoch) {
    nl_event_bus *bus = calloc(1, sizeof(*bus));
    if (!bus) return NULL;
    bus->publisher_id = publisher_id;
    bus->epoch = epoch;
    bus->sequence = 0;
    pthread_mutex_init(&bus->lock, NULL);
    return bus;
}

void nl_eventbus_destroy(nl_event_bus *bus) {
    subscriber_t *s;

    if (!bus) return;
    pthread_mutex_lock(&bus->lock);
    s = bus->subscribers;
    while (s) {
        subscriber_t *next = s->next;
        free(s);
        s = next;
    }
    bus->subscribers = NULL;
    bus->num_subscribers = 0;
    pthread_mutex_unlock(&bus->lock);
    pthread_mutex_destroy(&bus->lock);
    free(bus);
}

u64 nl_eventbus_next_seq(nl_event_bus *bus) {
    return __sync_fetch_and_add(&bus->sequence, 1);
}

nl_status nl_eventbus_publish(nl_event_bus *bus, const char *topic,
                              void *data, u32 len) {
    nl_event_callback callbacks[MAX_SUBSCRIBERS];
    void *userdatas[MAX_SUBSCRIBERS];
    int n_callbacks = 0;

    if (!bus || !topic) return NL_ERR;

    u64 seq = __sync_fetch_and_add(&bus->sequence, 1);

    nl_event *evt = calloc(1, sizeof(nl_event) + len);
    if (!evt) return NL_ERR;

    evt->publisher_id = bus->publisher_id;
    evt->epoch = bus->epoch;
    evt->sequence = seq;
    strncpy(evt->topic, topic, sizeof(evt->topic) - 1);
    evt->payload_len = len;
    if (data && len > 0) memcpy(evt->payload, data, len);

    pthread_mutex_lock(&bus->lock);
    for (subscriber_t *s = bus->subscribers; s; s = s->next) {
        if (strcmp(s->topic, topic) == 0 || strcmp(s->topic, "*") == 0) {
            callbacks[n_callbacks] = s->cb;
            userdatas[n_callbacks] = s->userdata;
            n_callbacks++;
            if (n_callbacks >= MAX_SUBSCRIBERS)
                break;
        }
    }
    pthread_mutex_unlock(&bus->lock);

    for (int i = 0; i < n_callbacks; i++)
        callbacks[i](evt, userdatas[i]);

    free(evt);
    return NL_OK;
}

nl_status nl_eventbus_subscribe(nl_event_bus *bus, const char *topic,
                                nl_event_callback cb, void *userdata) {
    int total;

    if (!bus || !topic || !cb) return NL_ERR;

    subscriber_t *s = calloc(1, sizeof(*s));
    if (!s) return NL_ERR;

    strncpy(s->topic, topic, sizeof(s->topic) - 1);
    s->cb = cb;
    s->userdata = userdata;

    pthread_mutex_lock(&bus->lock);
    if (bus->num_subscribers >= MAX_SUBSCRIBERS) {
        pthread_mutex_unlock(&bus->lock);
        free(s);
        return NL_ERR;
    }
    s->next = bus->subscribers;
    bus->subscribers = s;
    bus->num_subscribers++;
    total = bus->num_subscribers;
    pthread_mutex_unlock(&bus->lock);

    NL_LOG_DBG("subscribed to '%s' (total=%d)", topic, total);
    return NL_OK;
}

nl_status nl_eventbus_unsubscribe(nl_event_bus *bus, const char *topic,
                                  nl_event_callback cb) {
    if (!bus || !topic || !cb) return NL_ERR;

    pthread_mutex_lock(&bus->lock);
    subscriber_t **prev = &bus->subscribers;
    subscriber_t *s = bus->subscribers;
    while (s) {
        if (strcmp(s->topic, topic) == 0 && s->cb == cb) {
            *prev = s->next;
            free(s);
            bus->num_subscribers--;
            pthread_mutex_unlock(&bus->lock);
            return NL_OK;
        }
        prev = &s->next;
        s = s->next;
    }
    pthread_mutex_unlock(&bus->lock);
    return NL_ERR;
}

nl_status nl_eventbus_get_snapshot(nl_event_bus *bus,
                                   nl_event_stream_state *state) {
    if (!bus || !state) return NL_ERR;
    pthread_mutex_lock(&bus->lock);
    state->publisher_id = bus->publisher_id;
    state->epoch = bus->epoch;
    state->last_sequence = bus->sequence;
    pthread_mutex_unlock(&bus->lock);
    return NL_OK;
}
