/* Modified for fm10k-controlpanel; original import digests are in SOURCE_MANIFEST.json. */
#include "netlab/hal.h"
#include "netlab/interface_id.h"
#include "netlab/log.h"
#include "netlab/mcast_readback.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fm_sdk.h>
#include <api/fm_api_multicast.h>

static int append_text(char *buf, size_t buf_size, size_t *off,
                       const char *fmt, ...) {
    va_list ap;
    int n;

    if (!buf || !off || *off >= buf_size)
        return -1;
    va_start(ap, fmt);
    n = vsnprintf(buf + *off, buf_size - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= buf_size - *off) {
        buf[buf_size - 1] = '\0';
        return -1;
    }
    *off += (size_t)n;
    return 0;
}

static fm_macaddr mac_to_sdk(const u8 mac[6]) {
    fm_macaddr value = 0;

    for (int i = 0; i < 6; i++)
        value = (value << 8) | mac[i];
    return value;
}

static void sdk_to_mac(fm_macaddr value, u8 mac[6]) {
    for (int i = 5; i >= 0; i--) {
        mac[i] = (u8)(value & 0xff);
        value >>= 8;
    }
}

static void fill_address(fm_multicastAddress *address, fm_int group,
                         u16 vid, const u8 mac[6]) {
    memset(address, 0, sizeof(*address));
    address->addressType = FM_MCAST_ADDR_TYPE_L2MAC_VLAN;
    address->mcastGroup = group;
    address->info.mac.destMacAddress = mac_to_sdk(mac);
    address->info.mac.vlan = vid;
}

static bool valid_key(u16 vid, const u8 mac[6], int port) {
    return vid >= 1 && vid <= 4094 && mac && (mac[0] & 0x01) != 0 &&
           port > 0 && port < FM_MAX_LOGICAL_PORT;
}

/* Group handles are non-zero and bounded by the pinned SDK's logical-port
 * allocator. A lookup error or mismatched address is never absence. */
static bool group_handle_valid(fm_int group) {
    return group > 0 && group < FM_MAX_LOGICAL_PORT;
}

static bool l2_address_valid(const fm_multicastAddress *address) {
    return address->addressType == FM_MCAST_ADDR_TYPE_L2MAC_VLAN &&
        address->info.mac.vlan >= 1 && address->info.mac.vlan <= 4094 &&
        !(address->info.mac.destMacAddress & ~UINT64_C(0xffffffffffff)) &&
        (address->info.mac.destMacAddress & (UINT64_C(1) << 40));
}

static int find_group(int sw, u16 vid, const u8 mac[6], fm_int *group) {
    fm_multicastAddress address, actual;
    if (!group) return -1;
    *group = -1;
    fill_address(&address, -1, vid, mac);
    fm_status status = fmFindMcastGroupByAddress((fm_int)sw, &address, group);
    if (status == FM_ERR_MCAST_ADDR_NOT_ASSIGNED) return 0;
    if (status != FM_OK || !group_handle_valid(*group)) return -1;
    memset(&actual, 0, sizeof(actual));
    if (fmGetMcastGroupAddress(sw, *group, &actual) != FM_OK || !l2_address_valid(&actual) ||
        actual.info.mac.vlan != vid || actual.info.mac.destMacAddress != mac_to_sdk(mac)) return -1;
    return 1;
}

typedef struct { uint64_t *keys; unsigned capacity, count; } listener_keys;

static bool listener_key_add(listener_keys *seen, const fm_multicastListener *listener) {
    if (listener->port < 0 || listener->port >= FM_MAX_LOGICAL_PORT ||
        (listener->remoteFlag != FALSE && listener->remoteFlag != TRUE) ||
        seen->count >= FM_MAX_LOGICAL_PORT) return false;
    /* CPU port zero and listeners for another VLAN still count toward
     * completeness, even though only external matching-VLAN ports are shown. */
    uint64_t key = (((uint64_t)(unsigned)listener->port << 16) | listener->vlan) + 1;
    if (!seen->capacity || seen->count * 2 >= seen->capacity) {
        unsigned capacity = seen->capacity ? seen->capacity * 2 : 64;
        uint64_t *keys = calloc(capacity, sizeof(*keys));
        if (!keys) return false;
        for (unsigned i = 0; i < seen->capacity; ++i) if (seen->keys[i]) {
            unsigned slot = nl_mcast_key_slot(seen->keys[i], capacity - 1);
            while (keys[slot]) slot = (slot + 1) & (capacity - 1);
            keys[slot] = seen->keys[i];
        }
        free(seen->keys); seen->keys = keys; seen->capacity = capacity;
    }
    unsigned slot = nl_mcast_key_slot(key, seen->capacity - 1);
    while (seen->keys[slot] && seen->keys[slot] != key) slot = (slot + 1) & (seen->capacity - 1);
    if (seen->keys[slot]) return false;
    seen->keys[slot] = key; ++seen->count;
    return true;
}

typedef int (*listener_consumer)(const fm_multicastListener *, void *);
static int walk_listeners(int sw, fm_int group, listener_consumer consume, void *context) {
    fm_multicastListener current;
    listener_keys seen = {0};
    memset(&current, 0, sizeof(current));
    current.port = -1;
    fm_status status = fmGetMcastGroupListenerFirst(sw, group, &current);
    int count = 0;
    while (status == FM_OK) {
        if (!listener_key_add(&seen, &current) || (consume && consume(&current, context))) {
            free(seen.keys); return -1;
        }
        ++count;
        fm_multicastListener next;
        memset(&next, 0, sizeof(next)); next.port = -1;
        status = fmGetMcastGroupListenerNext(sw, group, &current, &next);
        if (status == FM_OK) current = next;
    }
    free(seen.keys);
    return status == FM_ERR_NO_MORE ? count : -1;
}

typedef struct { u16 vid; int port; bool present; } listener_query;
static int match_listener(const fm_multicastListener *listener, void *context) {
    listener_query *query = context;
    if (listener->port != query->port || listener->vlan != query->vid) return 0;
    if (listener->remoteFlag) return -1;
    query->present = true;
    return 0;
}

static int listener_present_by_group(int sw, fm_int group, u16 vid, int port) {
    listener_query query = {.vid = vid, .port = port};
    /* A matching first row cannot hide an error or cycle in the remainder. */
    return walk_listeners(sw, group, match_listener, &query) < 0 ? -1 : query.present ? 1 : 0;
}

static int group_listener_count(int sw, fm_int group) {
    return walk_listeners(sw, group, NULL, NULL);
}

int hal_l2_mcast_listener_present(int sw, u16 vid, const u8 mac[6], int port) {
    fm_int group = -1;
    if (!valid_key(vid, mac, port)) return -1;
    int found = find_group(sw, vid, mac, &group);
    return found <= 0 ? found : listener_present_by_group(sw, group, vid, port);
}

int hal_l2_mcast_listener_set(int sw, u16 vid, const u8 mac[6], int port) {
    fm_multicastAddress address;
    fm_multicastListener listener;
    fm_int group = -1;
    fm_status st;
    int found;
    bool created = false;

    if (!valid_key(vid, mac, port))
        return -1;
    found = find_group(sw, vid, mac, &group);
    if (found < 0)
        return -1;
    if (found == 0) {
        st = fmCreateMcastGroup((fm_int)sw, &group);
        if (st != FM_OK)
            return (int)st;
        created = true;
        fill_address(&address, group, vid, mac);
        st = fmSetMcastGroupAddress((fm_int)sw, group, &address);
        if (st == FM_OK)
            st = fmActivateMcastGroup((fm_int)sw, group);
        if (st != FM_OK) {
            (void)fmDeleteMcastGroup((fm_int)sw, group);
            return (int)st;
        }
    }
    found = listener_present_by_group(sw, group, vid, port);
    if (found != 0)
        return found > 0 ? 0 : -1;

    memset(&listener, 0, sizeof(listener));
    listener.port = port;
    listener.vlan = vid;
    st = fmAddMcastGroupListener((fm_int)sw, group, &listener);
    if (st != FM_OK && created) {
        (void)fmDeactivateMcastGroup((fm_int)sw, group);
        (void)fmDeleteMcastGroup((fm_int)sw, group);
    }
    if (st != FM_OK)
        NL_LOG_ERR("multicast owner listener add group=%d vid=%u port=%d: %s",
                   (int)group, vid, port, fmErrorMsg(st));
    return st == FM_OK ? 0 : (int)st;
}

int hal_l2_mcast_listener_delete(int sw, u16 vid, const u8 mac[6], int port) {
    fm_multicastListener listener;
    fm_int group = -1;
    fm_status st;
    int found;
    int count;

    if (!valid_key(vid, mac, port))
        return -1;
    found = find_group(sw, vid, mac, &group);
    if (found <= 0)
        return found == 0 ? 0 : -1;
    found = listener_present_by_group(sw, group, vid, port);
    if (found <= 0)
        return found == 0 ? 0 : -1;

    memset(&listener, 0, sizeof(listener));
    listener.port = port;
    listener.vlan = vid;
    st = fmDeleteMcastGroupListener((fm_int)sw, group, &listener);
    if (st != FM_OK)
        return (int)st;
    count = group_listener_count(sw, group);
    if (count < 0)
        return -1;
    if (count == 0) {
        st = fmDeactivateMcastGroup((fm_int)sw, group);
        if (st == FM_OK)
            st = fmDeleteMcastGroup((fm_int)sw, group);
        if (st != FM_OK)
            return (int)st;
    }
    return 0;
}

typedef struct {
    u16 vid;
    char text[8192];
    size_t offset;
    int count;
} listener_projection;

static int project_listener(const fm_multicastListener *listener, void *context) {
    listener_projection *projection = context;
    if (listener->vlan != projection->vid || !nl_ifid_is_user_port(listener->port)) return 0;
    if (listener->port < 1 || listener->port > 24 || listener->remoteFlag) return -1;
    if (append_text(projection->text, sizeof(projection->text), &projection->offset,
        "<listener port=\"%d\" vlan=\"%u\"/>", listener->port, listener->vlan)) return -1;
    ++projection->count;
    return 0;
}

int hal_l2_mcast_owner_format(int sw, char *buf, size_t buf_size) {
    _Static_assert(NETLAB_L2_MCAST_OWNER_MAX == NL_MCAST_READBACK_BYTES, "Multicast IPC size mismatch");
    fm_int group = -1, previous = 0;
    size_t off = 0;
    int groups = 0, listeners = 0;
    if (!buf || !buf_size) return -1;
    buf[0] = '\0';
    if (append_text(buf, buf_size, &off, "<multicast-owner status=\"ok\">")) goto failed;
    fm_status status = fmGetMcastGroupFirst(sw, &group);
    while (status == FM_OK) {
        if (!group_handle_valid(group) || group <= previous) goto failed;
        previous = group;
        fm_multicastAddress address;
        memset(&address, 0, sizeof(address));
        fm_status address_status = fmGetMcastGroupAddress(sw, group, &address);
        /* Addressless internal/flooding groups are explicitly outside this
         * projection. Every other SDK error makes the whole read fail. */
        if (address_status != FM_OK && address_status != FM_ERR_MCAST_ADDR_NOT_ASSIGNED) goto failed;
        if (address_status == FM_OK) {
            if (address.addressType < FM_MCAST_ADDR_TYPE_L2MAC_VLAN ||
                address.addressType > FM_MCAST_ADDR_TYPE_DSTIP_SRCIP_VLAN) goto failed;
            if (address.addressType == FM_MCAST_ADDR_TYPE_L2MAC_VLAN) {
                fm_int owner = -1;
                if (!l2_address_valid(&address) ||
                    fmFindMcastGroupByAddress(sw, &address, &owner) != FM_OK || owner != group) goto failed;
                listener_projection projection = {.vid = address.info.mac.vlan};
                if (walk_listeners(sw, group, project_listener, &projection) < 0) goto failed;
                if (projection.count) {
                    u8 mac[6]; sdk_to_mac(address.info.mac.destMacAddress, mac);
                    if (append_text(buf, buf_size, &off,
                        "<group id=\"%d\" vlan=\"%u\" mac=\"%02x:%02x:%02x:%02x:%02x:%02x\">%s</group>",
                        group, address.info.mac.vlan, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], projection.text)) goto failed;
                    ++groups; listeners += projection.count;
                }
            }
        }
        fm_int next = -1;
        status = fmGetMcastGroupNext(sw, group, &next);
        if (status == FM_OK) group = next;
    }
    if (status != FM_ERR_NO_MORE || append_text(buf, buf_size, &off,
        "<summary groups=\"%d\" listeners=\"%d\"/></multicast-owner>", groups, listeners)) goto failed;
    return (int)off;
failed:
    buf[0] = '\0';
    return -1;
}
