/* AAPL CORE Revision: 2.4.0
 *
 * Copyright (c) 2014-2016 Avago Technologies. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* Firmware protocol derived from AAPL CORE 2.4.0 eye.c/meas.c.
 * Adaptation: incremental bounded reads, checked acknowledgements, explicit
 * failures, cancellation and restoration. Results are measured XOR errors
 * between the offset sampler and mission sampler, not a PRBS certification.
 */
#include "fm10k_eye_scan.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

bool fm10k_eye_active(const fm10k_eye_scan *s) {
    return s && (s->state == EYE_PREPARING || s->state == EYE_RUNNING);
}
uint32_t fm10k_eye_decode_count(uint16_t e) {
    /* Firmware timeout, never a measured error count. */
    if (e == 0xffff) return UINT32_MAX;
    return e & 0xe000 ? (uint32_t)(0x1000 | (e & 0xfff)) << (((e >> 12) & 15) - 1) : e & 0x1fff;
}
static int serdes_set(fm10k_eye_scan *s, unsigned irq, unsigned data) {
    uint32_t reply = 0;
    int rc=s->io.serdes(s->io.context, irq, data, &reply);
    if (rc || (reply & 255) != (irq & 255)) {
        fprintf(stderr,"FM10840 eye: SerDes irq=0x%x data=0x%x reply=0x%x transport=%d\n",irq,data,reply,rc);
        return -1;
    }
    return 0;
}
static int master_set(fm10k_eye_scan *s, unsigned data) {
    uint32_t reply = 0;
    int rc=s->io.master(s->io.context, data, &reply, true);
    if (rc || (reply & 255) != 0x2f) {
        fprintf(stderr,"FM10840 eye: master data=0x%x reply=0x%x transport=%d\n",data,reply,rc);
        return -1;
    }
    return 0;
}
static void finish(fm10k_eye_scan *s, int state, const char *error) {
    int failed = 0;
    uint32_t actual = 0;
    if (s->column_pending) {
        uint32_t ack;
        if (s->io.read(s->io.context, 0x08, &ack) || (ack & 0x8000) || !(ack & 0x3ff)) failed = 1;
    }
    if (error && *error) {
        snprintf(s->error, sizeof(s->error), "%s", error);
        snprintf(s->failure_reason, sizeof(s->failure_reason), "%s", error);
    }
    /* Do not short-circuit: try each independent restoration even if one fails. */
    if (s->configured) {
        if (serdes_set(s, 0x03, (s->target.compare_mode & 0x770) | 3)) failed = 1;
        if (s->io.compare(s->io.context, &actual) ||
            (actual & 0x770) != s->target.compare_mode) failed = 1;
        /* Match AAPL restore_serdes_state: latch/read and reset the sampler's
         * error counter before shutting down the PI. A completed matrix does
         * not by itself release the counter's measurement state. */
        if (serdes_set(s, 0x18, 3)) failed = 1;
        if (s->io.serdes(s->io.context, 0x1a, 0, &actual)) failed = 1;
        if (s->io.serdes(s->io.context, 0x1a, 0, &actual)) failed = 1;
        if (serdes_set(s, 0x17, 0)) failed = 1;
        if (serdes_set(s, 0x0f, 0x100)) failed = 1;
    }
    int restore_status=(s->prepared || s->configured) && s->io.restore?s->io.restore(s->io.context):0;
    if (restore_status) failed = 1;
    /* Firmware >= 0x1049 saves the DFE run state during pause, including
     * adaptive/RR enablement; 0x0f resumes that saved state. */
    /* -2 means the shared firmware could not be restored; resuming DFE
     * would depend on that missing state. Keep it paused for SDK recovery. */
    if (s->paused && restore_status!=-2 && serdes_set(s, 0x0a, 0x0f)) failed = 1;
    if (restore_status!=-2) s->paused = false;
    s->restored = !failed;
    s->restore_failed = failed;
    s->state = failed ? EYE_FAILED : state;
    if (failed) snprintf(s->error, sizeof(s->error), "restore_failed");
    fprintf(stderr,"FM10840 eye: finished state=%d reason=%s restored=%d columns=%u row=%u pending=%d\n",
            s->state,s->failure_reason,s->restored,s->columns_done,s->row,s->column_pending);
    s->updated_ms = s->io.now(s->io.context);
}
int fm10k_eye_start(fm10k_eye_scan *s, const fm10k_eye_io *io,
                    const fm10k_eye_target *target, const char *id,
                    unsigned x_resolution, unsigned y_step, unsigned dwell_bits, double wall) {
    if (!s || !io || !target || !id || strlen(id) != 32 ||
        strspn(id, "0123456789abcdef") != 32 || fm10k_eye_active(s) || s->restore_failed ||
        !io->serdes || !io->master || !io->read || !io->write || !io->compare || !io->signal || !io->now ||
        (x_resolution != 16 && x_resolution != 32 && x_resolution != 64) ||
        (y_step != 1 && y_step != 2 && y_step != 4 && y_step != 8) ||
        dwell_bits < 100000 || dwell_bits > 10000000 || dwell_bits % 20 ||
        (target->firmware >> 16) < 0x1049 || target->protocol == 0xffff ||
        ((target->internal_loopback || target->temporary_master) && (!io->prepare || !io->restore)) ||
        !target->phase_multiplier || target->phase_multiplier > 8 || !target->sbus || target->sbus >= 0xfd)
        return -1;
    memset(s, 0, sizeof(*s));
    s->io = *io; s->target = *target;
    memcpy(s->id, id, 33);
    s->x_resolution = x_resolution; s->y_step = y_step;
    s->x_points = 2 * x_resolution + 1; s->y_points = 256 / y_step;
    s->x_step = target->phase_multiplier * 64 / x_resolution;
    s->dwell_bits = dwell_bits;
    s->started_ms = s->updated_ms = io->now(io->context); s->started_at = wall;
    s->state = EYE_PREPARING;
    if (!target->internal_loopback && io->signal(io->context)) {
        finish(s, EYE_FAILED, "no_signal"); return 0;
    }
    /* An error reply can follow a successful write: mark it before issuing. */
    s->paused = true;
    if (serdes_set(s, 0x0a, 0)) finish(s, EYE_FAILED, "dfe_pause_failed");
    return 0;
}
void fm10k_eye_cancel(fm10k_eye_scan *s, const char *reason) {
    if (!fm10k_eye_active(s)) return;
    s->cancel_requested = true;
    if (reason) snprintf(s->error, sizeof(s->error), "%s", reason);
}
static int setup(fm10k_eye_scan *s) {
    /* FM10000 D6 RX register clock is 20 bits. The 0x101a master shipped
     * with the older protocol uses single dwell (matching its AAPL source);
     * newer AAPL 2.4 masters use double dwell. Never mix these counters. */
    unsigned scale=s->target.temporary_master || s->target.master_firmware==0x101a0001 ? 1 : 2;
    unsigned words = s->dwell_bits * scale / 20;
    uint32_t actual;
    s->configured = true; /* Restore partial setup even if a command fails. */
    if (serdes_set(s, 0x0103, words & 0xffff) || serdes_set(s, 0x0203, words >> 16) ||
        master_set(s, 0x1000 | s->target.sbus) || master_set(s, 0x5000) ||
        master_set(s, 0x6000 | s->target.phase_multiplier) || master_set(s, 0x7000) ||
        master_set(s, 0x2000) || master_set(s, 0x3001) || master_set(s, 0x4001) ||
        serdes_set(s, 0x03, 0x103) || s->io.compare(s->io.context, &actual) ||
        (actual & 0x770) != 0x100) return -1;
    return 0;
}
static void begin_gather(fm10k_eye_scan *s, unsigned command, uint64_t now) {
    s->row = 0; s->read_index = 1; s->column_ms = now;
    /* A failed transport reply can follow a successful hardware write. */
    s->column_pending = true;
    uint32_t unused;
    if (s->io.write(s->io.context, 0x11, 1) || s->io.write(s->io.context, 0x12, 0) ||
        s->io.master(s->io.context, command, &unused, false))
        finish(s, EYE_FAILED, "column_start_failed");
}
void fm10k_eye_tick(fm10k_eye_scan *s) {
    if (!fm10k_eye_active(s)) return;
    uint64_t now = s->io.now(s->io.context);
    s->updated_ms = now;
    if (now < s->started_ms || now - s->started_ms > 300000) {
        finish(s, EYE_FAILED, "scan_timeout"); return;
    }
    if (s->cancel_requested && !s->column_pending) {
        finish(s, EYE_CANCELLED, NULL); return;
    }
    if (s->state == EYE_PREPARING && !s->column_pending) {
        uint32_t flags;
        if (s->io.serdes(s->io.context, 0x126, 0x0b00, &flags)) {
            finish(s, EYE_FAILED, "dfe_status_failed"); return;
        }
        if ((flags & 0x200) && !s->target.internal_loopback) {
            finish(s, EYE_FAILED, "no_signal"); return;
        }
        /* LOS suspends a DFE operation even when its active bits remain set.
         * It may proceed to internal signal preparation after a checked pause. */
        if (!(flags & 0x200) && (flags & 0x37)) {
            if (now - s->started_ms > 50000) finish(s, EYE_FAILED, "dfe_timeout");
            return;
        }
        if ((s->target.internal_loopback || s->target.temporary_master) && !s->preparation_done) {
            s->prepared = true;
            int rc=s->io.prepare(s->io.context);
            if (rc<0) finish(s, EYE_FAILED, rc==-2?"master_firmware_setup_failed":"loopback_setup_failed");
            else if(rc==0) s->preparation_done=true;
            else if(now-s->started_ms>120000) finish(s,EYE_FAILED,"dfe_timeout");
            return; /* Allow one owner poll for the internal RX to settle. */
        }
        if (s->io.signal(s->io.context)) { finish(s, EYE_FAILED, "no_signal"); return; }
        if (setup(s)) { finish(s, EYE_FAILED, "eye_setup_failed"); return; }
        /* A mission sample establishes the firmware's phase center. */
        s->priming = true;
        begin_gather(s, 0xc000, now);
        return;
    }
    if (!s->column_pending) {
        if (s->columns_done >= s->x_points) { finish(s, EYE_COMPLETE, NULL); return; }
        if (s->io.signal(s->io.context)) { finish(s, EYE_FAILED, "signal_lost"); return; }
        int phase = ((int)s->columns_done - (int)s->x_points / 2) * (int)s->x_step;
        begin_gather(s, 0xb000 | ((unsigned)phase & 0x7ff), now);
        return;
    }
    if (now - s->column_ms > 15000) { finish(s, EYE_FAILED, "column_timeout"); return; }
    unsigned points = s->priming ? 1 : s->y_points;
    for (unsigned blocks = 0; s->row < points && blocks < 32; ++blocks) {
        uint32_t available, pair1, pair2;
        if (s->io.write(s->io.context, 0x11, s->read_index) ||
            s->io.read(s->io.context, 0x12, &available)) {
            finish(s, EYE_FAILED, "buffer_read_failed"); return;
        }
        if (available < s->read_index) return;
        if (available > (points + 3) / 4 ||
            s->io.read(s->io.context, 0x13, &pair1) || s->io.read(s->io.context, 0x16, &pair2)) {
            finish(s, EYE_FAILED, "buffer_sequence_invalid"); return;
        }
        uint16_t packed[4] = {(uint16_t)(pair1 >> 16), (uint16_t)pair1,
                              (uint16_t)(pair2 >> 16), (uint16_t)pair2};
        /* Firmware run-length encoding: every skipped group repeats these
         * four samples. A timeout or missing group is never a zero sample. */
        unsigned end = available * 4;
        while (s->row < end && s->row < points) {
            uint32_t count = fm10k_eye_decode_count(packed[s->row % 4]);
            if (count == UINT32_MAX) { finish(s, EYE_FAILED, "sample_timeout"); return; }
            if (!s->priming) s->errors[s->columns_done][s->row] = count;
            ++s->row;
        }
        s->read_index = available + 1;
        if (s->io.now(s->io.context) - now >= 8) return;
    }
    if (s->row == points) {
        uint32_t ack;
        /* io->read(0x08) addresses the master, all other reads the controller. */
        if (s->io.read(s->io.context, 0x08, &ack)) { finish(s, EYE_FAILED, "column_ack_failed"); return; }
        if ((ack & 0x8000) || !(ack & 0x3ff)) return;
        /* GATHER returns a firmware result, not a SET command echo. */
        s->column_pending = false;
        if (s->priming) {
            uint32_t center;
            if (s->io.master(s->io.context, 0x0008, &center, true) ||
                master_set(s, 0x2000 | ((unsigned)-128 & 0x7ff)) ||
                master_set(s, 0x3000 | s->y_points) || master_set(s, 0x4000 | s->y_step)) {
                finish(s, EYE_FAILED, "eye_setup_failed"); return;
            }
            s->phase_center = (int16_t)center;
            s->priming = false;
            s->state = EYE_RUNNING;
            if (s->cancel_requested) finish(s, EYE_CANCELLED, NULL);
            return;
        }
        ++s->columns_done;
        if (s->cancel_requested) finish(s, EYE_CANCELLED, NULL);
        else if (s->columns_done == s->x_points) finish(s, EYE_COMPLETE, NULL);
    }
}
typedef struct { char *p; size_t cap, used; bool failed; } writer;
static void emit(writer *w, const char *format, ...) {
    if (w->failed) return;
    va_list args; va_start(args, format);
    int n = vsnprintf(w->p + w->used, w->cap - w->used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= w->cap - w->used) w->failed = true;
    else w->used += (size_t)n;
}
int fm10k_eye_format(const fm10k_eye_scan *s, unsigned column, char *out, size_t capacity) {
    static const char *states[] = {"idle", "preparing", "running", "complete", "cancelled", "failed"};
    if (!s || !out || !capacity || column > s->columns_done) return -1;
    writer w = {.p=out,.cap=capacity};
    if (s->state == EYE_IDLE) { emit(&w, "{\"state\":\"idle\",\"source\":\"serdes-hardware\"}"); return w.failed ? -1 : 0; }
    unsigned count = s->y_points > 128 ? 2 : 4;
    unsigned last = column + count;
    if (last > s->columns_done) last = s->columns_done;
    emit(&w, "{\"id\":\"%s\",\"state\":\"%s\",\"source\":\"serdes-hardware\","
        "\"port\":%d,\"epl\":%d,\"lane\":%d,\"speed_mbps\":%d,"
        "\"x_points\":%u,\"y_points\":%u,\"x_resolution\":%u,\"x_step\":%u,\"y_step\":%u,"
        "\"y_min\":-128,\"dwell_bits\":%u,\"columns_done\":%u,\"column_offset\":%u,"
        "\"started_at\":%.6f,\"elapsed_ms\":%llu,\"restored\":%s,\"restore_failed\":%s,"
        "\"error\":\"%s\",\"failure_reason\":\"%s\",\"firmware\":%u,\"master_firmware\":%u,\"protocol\":%u,"
        "\"phase_multiplier\":%u,\"compare_mode_before\":%u,\"vertical_unit\":\"DAC\","
        "\"phase_center\":%d,\"signal_source\":\"%s\",\"dwell_scale\":%u,\"rx_clock_divider\":20,"
        "\"temporary_master\":%s,\"sampling_master_firmware\":%u,"
        "\"measurement\":\"offset-sampler-xor\",\"errors\":[",
        s->id, fm10k_eye_active(s) && s->cancel_requested ? "cancelling" : states[s->state],
        s->target.port,s->target.epl,s->target.lane,s->target.speed_mbps,
        s->x_points,s->y_points,s->x_resolution,s->x_step,s->y_step,s->dwell_bits,s->columns_done,column,
        s->started_at,(unsigned long long)(s->updated_ms-s->started_ms),s->restored?"true":"false",
        s->restore_failed?"true":"false",s->error,s->failure_reason,s->target.firmware,s->target.master_firmware,
        s->target.protocol,s->target.phase_multiplier,s->target.compare_mode,s->phase_center,
        s->target.internal_loopback?"internal_prbs31_loopback":"external",
        s->target.temporary_master || s->target.master_firmware==0x101a0001?1:2,
        s->target.temporary_master?"true":"false",
        s->target.temporary_master?0x101a0001:s->target.master_firmware);
    for (unsigned x=column; x<last; ++x) {
        emit(&w, "%s[",x==column?"":",");
        for (unsigned y=0; y<s->y_points; ++y) emit(&w,"%s%u",y?",":"",s->errors[x][y]);
        emit(&w,"]");
    }
    emit(&w,"]}");
    return w.failed ? -1 : 0;
}
