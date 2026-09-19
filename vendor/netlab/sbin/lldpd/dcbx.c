#include "dcbx.h"
#include "lldp_xml.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

static bool ets_valid(const u8 *map, const u8 *bw, const u8 *tsa, int cap) {
    unsigned total = 0;
    bool ets = false;
    if (cap < 1 || cap > 8) return false;
    for (int i = 0; i < 8; i++) {
        if (map[i] >= cap || bw[i] > 100) return false;
        if (tsa[i] != 0 && tsa[i] != 1 && tsa[i] != 2 && tsa[i] != 255) return false;
        if (tsa[i] == 2) { total += bw[i]; ets = true; }
    }
    return !ets || total == 100;
}

static bool app_valid(const dcbx_app *app) {
    return app->priority < 8 && app->selector >= 1 && app->selector <= 5 &&
           (app->selector != 5 || app->protocol <= 63);
}

static int append(u8 *buf, int size, int offset, const u8 *v, int n) {
    if (!buf || offset < 0 || n > 511 || offset > size - n - 2) return -1;
    buf[offset++] = (u8)(254 | (n >> 8));
    buf[offset++] = (u8)n;
    memcpy(buf + offset, v, (size_t)n);
    return offset + n;
}

int dcbx_append(u8 *buf, int size, int offset, const dcbx_state *s) {
    if (!s || !s->enabled) return offset;
    if (s->malformed || !s->pfc_present || !s->ets_present || !s->app_present ||
        s->pfc_capability < 1 || s->pfc_capability > 8 || s->n_apps < 0 || s->n_apps > DCBX_MAX_APPS ||
        !ets_valid(s->priority_tc, s->bandwidth, s->tsa, s->ets_capability)) return -1;
    u8 v[5 + 3 * DCBX_MAX_APPS] = {0, 0x80, 0xc2, 9};
    /* Local policy is authoritative. Never advertise willing or copy peer policy. */
    v[4] = s->ets_capability & 7;
    for (int i = 0; i < 4; i++) v[5 + i] = (u8)(s->priority_tc[2*i] << 4 | s->priority_tc[2*i+1]);
    memcpy(v + 9, s->bandwidth, 8);
    memcpy(v + 17, s->tsa, 8);
    offset = append(buf, size, offset, v, 25);
    if (offset < 0) return -1;
    v[3] = 10; v[4] = 0; /* ETS recommendation uses the same local policy. */
    offset = append(buf, size, offset, v, 25);
    if (offset < 0) return -1;
    v[3] = 11; v[4] = s->pfc_capability; v[5] = s->pfc_mask;
    offset = append(buf, size, offset, v, 6);
    if (offset < 0) return -1;
    v[3] = 12; v[4] = 0;
    for (int i = 0; i < s->n_apps; i++) {
        if (!app_valid(&s->apps[i])) return -1;
        v[5+3*i] = (u8)(s->apps[i].priority << 5 | s->apps[i].selector);
        v[6+3*i] = (u8)(s->apps[i].protocol >> 8);
        v[7+3*i] = (u8)s->apps[i].protocol;
    }
    return append(buf, size, offset, v, 5 + 3 * s->n_apps);
}

void dcbx_parse(const u8 *v, int n, dcbx_state *s) {
    if (!s || !v || n < 4 || memcmp(v, "\x00\x80\xc2", 3)) return;
    int subtype = v[3];
    if (subtype < 9 || subtype > 12) return;
    s->enabled = true;
    if (subtype == 9 || subtype == 10) {
        bool *present = subtype == 9 ? &s->ets_present : &s->recommendation_present;
        if (*present || n != 25) { s->malformed = true; return; }
        *present = true;
        u8 *map = subtype == 9 ? s->priority_tc : s->recommendation_priority_tc;
        u8 *bw = subtype == 9 ? s->bandwidth : s->recommendation_bandwidth;
        u8 *tsa = subtype == 9 ? s->tsa : s->recommendation_tsa;
        for (int i = 0; i < 4; i++) { map[2*i] = v[5+i] >> 4; map[2*i+1] = v[5+i] & 15; }
        memcpy(bw, v + 9, 8); memcpy(tsa, v + 17, 8);
        int cap = 8;
        if (subtype == 9) {
            s->ets_willing = (v[4] & 128) != 0; s->ets_cbs = (v[4] & 64) != 0;
            s->ets_capability = (v[4] & 7) ? v[4] & 7 : 8;
            cap = s->ets_capability;
        }
        if (!ets_valid(map, bw, tsa, cap)) s->malformed = true;
    } else if (subtype == 11) {
        if (s->pfc_present || n != 6) { s->malformed = true; return; }
        s->pfc_present = true;
        s->pfc_willing = (v[4] & 128) != 0; s->pfc_mbc = (v[4] & 64) != 0;
        s->pfc_capability = v[4] & 15; s->pfc_mask = v[5];
        unsigned classes = 0;
        for (int i = 0; i < 8; i++) if (s->pfc_mask & (1U << i)) classes++;
        if (s->pfc_capability < 1 || s->pfc_capability > 8 || classes > s->pfc_capability)
            s->malformed = true;
    } else {
        if (s->app_present || n < 5 || (n-5) % 3 || (n-5)/3 > DCBX_MAX_APPS) {
            s->malformed = true; return;
        }
        s->app_present = true; s->n_apps = (n-5)/3;
        for (int i = 0; i < s->n_apps; i++) {
            dcbx_app *app = &s->apps[i];
            app->priority = v[5+3*i] >> 5; app->selector = v[5+3*i] & 7;
            app->protocol = (u16)(v[6+3*i] << 8 | v[7+3*i]);
            if (!app_valid(app)) s->malformed = true;
            for (int j = 0; j < i; j++)
                if (app->selector == s->apps[j].selector && app->protocol == s->apps[j].protocol &&
                    app->priority == s->apps[j].priority) s->malformed = true;
        }
    }
}

static bool vector(const char *start, const char *end, const char *name, u8 *out, int maximum) {
    char value[128], *save = NULL;
    if (lldp_xml_leaf(start, end, name, value, sizeof(value))) return false;
    char *p = strtok_r(value, " ", &save);
    for (int i = 0; i < 8; i++) {
        int n;
        if (!p || !lldp_parse_int_text(p, 0, maximum, &n)) return false;
        out[i] = (u8)n; p = strtok_r(NULL, " ", &save);
    }
    return !p;
}

bool dcbx_load_xml(const char *start, const char *end, dcbx_state *s) {
    if (!s) return false;
    memset(s, 0, sizeof(*s));
    if (!start || !end || start >= end) return true;
    const char *p = strstr(start, "<dcbx>");
    if (!p || p >= end) return true;
    const char *q = strstr(p, "</dcbx>");
    if (!q || q > end) return false;
    char value[32]; int mask;
    if (lldp_xml_leaf(p, q, "enabled", value, sizeof(value))) return false;
    if (!strcmp(value, "false")) return true;
    if (strcmp(value, "true")) return false;
    s->enabled = true; s->pfc_capability = s->ets_capability = 8;
    s->pfc_present = s->ets_present = s->app_present = true;
    if (lldp_xml_leaf(p, q, "pfc-mask", value, sizeof(value)) ||
        !lldp_parse_int_text(value, 0, 255, &mask)) return false;
    s->pfc_mask = (u8)mask;
    if (!vector(p,q,"priority-map",s->priority_tc,7) || !vector(p,q,"bandwidth",s->bandwidth,100) ||
        !vector(p,q,"tsa-map",s->tsa,2) || !ets_valid(s->priority_tc,s->bandwidth,s->tsa,8)) return false;
    const char *a = p;
    while ((a = strstr(a, "<application>")) && a < q) {
        const char *b = strstr(a, "</application>");
        int selector, protocol, priority;
        if (!b || b > q || s->n_apps == DCBX_MAX_APPS) return false;
        if (lldp_xml_leaf(a,b,"selector",value,sizeof(value)) || !lldp_parse_int_text(value,1,5,&selector) ||
            lldp_xml_leaf(a,b,"protocol",value,sizeof(value)) || !lldp_parse_int_text(value,0,65535,&protocol) ||
            lldp_xml_leaf(a,b,"priority",value,sizeof(value)) || !lldp_parse_int_text(value,0,7,&priority)) return false;
        dcbx_app app = {(u8)priority,(u8)selector,(u16)protocol};
        if (!app_valid(&app)) return false;
        s->apps[s->n_apps++] = app;
        a = b + strlen("</application>");
    }
    return true;
}

const char *dcbx_compare(const dcbx_state *a, const dcbx_state *b) {
    if (!a || !a->enabled) return "disabled";
    if (a->malformed) return "local-error";
    if (!b || !b->enabled) return "no-peer-dcbx";
    if (b->malformed) return "malformed-peer";
    if (!b->pfc_present) return "missing-pfc";
    if (a->pfc_mask != b->pfc_mask) return "pfc-mismatch";
    if (!b->ets_present) return "missing-ets";
    if (memcmp(a->priority_tc,b->priority_tc,8) || memcmp(a->bandwidth,b->bandwidth,8) ||
        memcmp(a->tsa,b->tsa,8)) return "ets-mismatch";
    if (!b->app_present) return "missing-app";
    for (int i = 0; i < a->n_apps; i++) {
        bool found = false;
        for (int j = 0; j < b->n_apps; j++) {
            if (a->apps[i].selector != b->apps[j].selector || a->apps[i].protocol != b->apps[j].protocol) continue;
            if (a->apps[i].priority != b->apps[j].priority) return "app-mismatch";
            found = true;
        }
        if (!found) return "app-mismatch";
    }
    return "matched"; /* Advertised policy matches; does not prove endpoint enforcement. */
}

static bool fmt(char *buf, size_t size, size_t *off, const char *format, ...) {
    if (*off >= size) return false;
    va_list args; va_start(args, format);
    int n = vsnprintf(buf + *off, size - *off, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= size - *off) return false;
    *off += (size_t)n;
    return true;
}

int dcbx_format_xml(char *buf, size_t size, const char *tag, const dcbx_state *s) {
    size_t off = 0;
    if (!buf || !s || !tag || (strcmp(tag,"local") && strcmp(tag,"remote"))) return -1;
    if (!fmt(buf,size,&off,"<%s enabled=\"%s\" malformed=\"%s\" pfc-present=\"%s\" ets-present=\"%s\" app-present=\"%s\" pfc-mask=\"%u\" pfc-capability=\"%u\" pfc-willing=\"%s\" ets-willing=\"%s\" ets-capability=\"%u\"",
        tag,s->enabled?"true":"false",s->malformed?"true":"false",s->pfc_present?"true":"false",
        s->ets_present?"true":"false",s->app_present?"true":"false",s->pfc_mask,s->pfc_capability,
        s->pfc_willing?"true":"false",s->ets_willing?"true":"false",s->ets_capability)) return -1;
    const char *names[] = {"priority-map","bandwidth","tsa-map"};
    const u8 *vectors[] = {s->priority_tc,s->bandwidth,s->tsa};
    for (int k = 0; k < 3; k++) {
        if (!fmt(buf,size,&off," %s=\"",names[k])) return -1;
        for (int i = 0; i < 8; i++) if (!fmt(buf,size,&off,"%s%u",i?" ":"",vectors[k][i])) return -1;
        if (!fmt(buf,size,&off,"\"")) return -1;
    }
    if (!fmt(buf,size,&off,">")) return -1;
    for (int i = 0; i < s->n_apps; i++)
        if (!fmt(buf,size,&off,"<application selector=\"%u\" protocol=\"%u\" priority=\"%u\"/>",
                 s->apps[i].selector,s->apps[i].protocol,s->apps[i].priority)) return -1;
    if (!fmt(buf,size,&off,"</%s>",tag)) return -1;
    return (int)off;
}
