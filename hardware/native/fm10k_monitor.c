#include "fm10k_monitor.h"

#include <ctype.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define SAMPLE_PERIOD_MS 5000U
#define STALE_MS 15000U
#define IDENTITY_PERIOD_MS 60000U

static void measure(fm10k_measurement *m, bool valid, double value,
                     uint64_t now, double wall) {
    m->valid = valid && isfinite(value);
    if (m->valid) {
        m->available = true;
        m->value = value;
        m->sampled_ms = now;
        m->sampled_at = wall;
    }
}
static bool fresh(const fm10k_measurement *m, uint64_t now) {
    return m->available && m->valid && now >= m->sampled_ms &&
           now - m->sampled_ms < STALE_MS;
}
static const char *quality(const fm10k_measurement *m, uint64_t now) {
    return fresh(m, now) ? "valid" : m->available ? "stale" : "unavailable";
}
static bool optical_identity_qualified(const fm10k_monitor *s, int i) {
    if (!s->identity_valid[i]) return false;
    const uint8_t *raw = s->identity[i];
    unsigned sum = 0;
    for (int n = 0; n < 95; ++n) sum += raw[n];
    /* LEAP's manufacturer documentation specifies a CXP-like map. Only
     * the identified FCI module is qualified, never arbitrary QSFP DOM. */
    return (sum & 255) == raw[95] &&
        memcmp(raw + 24, "FCI MergeOptics ", 16) == 0 &&
        memcmp(raw + 43, "10124588-24A", 12) == 0;
}
void fm10k_monitor_init(fm10k_monitor *s, fm10k_bus *bus) {
    memset(s, 0, sizeof(*s));
    s->bus = bus;
    s->tach_factor = 5400000;
}
int fm10k_monitor_curve(fm10k_monitor *s, const fm10k_fan_curve *curve) {
    if (!s || fm10k_fan_validate(curve)) return FM10K_INVALID;
    fm10k_fan_state before = s->fan;
    int rc = fm10k_fan_apply(s->bus, curve);
    if (!rc) {
        s->fan = (fm10k_fan_state){.curve = *curve, .curve_valid = true};
        s->fan_due = 0;
        return FM10K_OK;
    }
    ++s->io_errors;
    if (before.curve_valid && !fm10k_fan_apply(s->bus, &before.curve)) {
        /* A failed curve edit cancels any manual test and restores the
         * previous autonomous LUT, never an indefinite manual PWM. */
        s->fan = (fm10k_fan_state){.curve = before.curve, .curve_valid = true};
        s->fan_due = 0;
        return FM10K_IO;
    }
    s->fan = before;
    s->fan.manual = false;
    s->fan.manual_deadline_ms = 0;
    s->fan.failsafe = true;
    (void)fm10k_fan_full(s->bus);
    return FM10K_ROLLBACK_FAILED;
}
int fm10k_monitor_fan_capture(fm10k_monitor *s, fm10k_fan_snapshot *out) {
    if (!s || !out) return FM10K_INVALID;
    memset(out, 0, sizeof(*out));
    /* A configuration transaction cannot capture an expiring manual PWM as
     * an indefinitely restorable setting. Let the test finish first. */
    if (s->fan.manual) return FM10K_INVALID;
    int rc = fm10k_fan_image_read(s->bus, &out->image);
    if (rc || !fm10k_fan_image_matches(&out->image, s->fan.curve_valid ? &s->fan.curve : NULL))
        return FM10K_IO;
    out->curve_valid = s->fan.curve_valid;
    out->curve = s->fan.curve;
    out->valid = true;
    return FM10K_OK;
}
static bool fan_protection_required(const fm10k_monitor *s, const fm10k_fan_curve *f, uint64_t now) {
    if (!f || !fresh(&s->temperatures[0], now)) return true;
    double temperature = s->temperatures[0].value;
    return temperature >= f->critical_c ||
        (s->fan.failsafe && temperature > f->critical_c - f->hysteresis_c);
}
int fm10k_monitor_fan_restore(fm10k_monitor *s, const fm10k_fan_snapshot *before, uint64_t now) {
    if (!s || !before || !before->valid) return FM10K_INVALID;
    const fm10k_fan_curve *curve = before->curve_valid ? &before->curve : NULL;
    bool full = fan_protection_required(s, curve, now);
    int rc = fm10k_fan_image_restore(s->bus, &before->image, curve, full);
    if (!rc) {
        s->fan = (fm10k_fan_state){.curve = before->curve,
            .curve_valid = before->curve_valid, .failsafe = full};
        fm10k_fan_snapshot after;
        if (fm10k_monitor_fan_capture(s, &after) || !fm10k_fan_snapshot_equal(before, &after))
            rc = FM10K_IO;
    }
    if (rc) {
        ++s->io_errors;
        s->fan.manual = false;
        s->fan.manual_deadline_ms = 0;
        s->fan.failsafe = true;
        (void)fm10k_fan_full(s->bus);
    }
    s->fan_due = 0;
    return rc;
}
int fm10k_monitor_fan_apply(fm10k_monitor *s, const fm10k_fan_curve *curve,
                            const fm10k_fan_snapshot *before, uint64_t now) {
    fm10k_fan_snapshot actual;
    if (!s || !before || fm10k_fan_validate(curve)) return FM10K_INVALID;
    if (fm10k_monitor_fan_capture(s, &actual) || !fm10k_fan_snapshot_equal(before, &actual))
        return FM10K_IO;
    bool full = fan_protection_required(s, curve, now);
    int rc = fm10k_fan_configure(s->bus, curve, full);
    if (!rc) {
        s->fan = (fm10k_fan_state){.curve = *curve, .curve_valid = true, .failsafe = full};
        rc = fm10k_monitor_fan_capture(s, &actual);
        if (!rc && !fm10k_fan_curve_equal(&actual.curve, curve)) rc = FM10K_IO;
    }
    s->fan_due = 0;
    if (!rc) return FM10K_OK;
    ++s->io_errors;
    return fm10k_monitor_fan_restore(s, before, now) ? FM10K_ROLLBACK_FAILED : FM10K_IO;
}
int fm10k_monitor_manual(fm10k_monitor *s, int pwm, int seconds, uint64_t now) {
    if (!s || s->fan.failsafe) return FM10K_INVALID;
    int rc = fm10k_fan_manual(s->bus, &s->fan, pwm, seconds, now,
                              fresh(&s->temperatures[0], now), s->temperatures[0].value);
    s->fan_due = 0;
    if (rc == FM10K_IO) ++s->io_errors;
    return rc;
}
int fm10k_monitor_step(fm10k_monitor *s, uint64_t now, double wall) {
    if (!s || !s->bus || !isfinite(wall) || wall < 0) return FM10K_INVALID;
    /* Expiry is checked on every scheduler turn, even between slow OBT
     * identity chunks. It never depends on a browser remaining connected. */
    if (s->fan.manual && now >= s->fan.manual_deadline_ms) {
        int rc = fm10k_fan_tick(s->bus, &s->fan, now,
                                fresh(&s->temperatures[0], now), s->temperatures[0].value);
        s->fan_due = 0;
        if (rc) ++s->io_errors;
        return rc;
    }
    if (now >= s->fan_due) {
        fm10k_fan_sample sample;
        int rc = fm10k_fan_read(s->bus, &sample);
        s->fan_readback = sample;
        measure(&s->temperatures[0], sample.core_valid, sample.core_c, now, wall);
        measure(&s->pwm, sample.pwm_valid, sample.pwm * 100.0 / 255.0, now, wall);
        /* Raw sentinel counts remain visible as diagnostics. RPM validity
         * is decided separately by fm10k_tach_rpm(). */
        measure(&s->tach, sample.tach_read, sample.tach_count, now, wall);
        if (sample.pwm_valid) s->pwm_mode = sample.pwm_mode;
        int control = fm10k_fan_tick(s->bus, &s->fan, now,
                                     fresh(&s->temperatures[0], now), s->temperatures[0].value);
        s->fan_due = now + SAMPLE_PERIOD_MS;
        ++s->samples;
        if (rc || control) ++s->io_errors;
        return control ? control : rc;
    }
    for (int i = 0; i < 2; ++i) {
        if (now < s->obt_due[i]) continue;
        fm10k_obt_sample sample;
        int rc = fm10k_obt_read(s->bus, i + 1, &sample);
        measure(&s->temperatures[i + 1], sample.temperature_valid, sample.temperature_c, now, wall);
        measure(&s->tx[i], sample.tx_valid, sample.tx_enabled, now, wall);
        measure(&s->tx_cdr[i], sample.diagnostic_valid, sample.tx_cdr, now, wall);
        measure(&s->rx_cdr[i], sample.diagnostic_valid, sample.rx_cdr, now, wall);
        measure(&s->rx_enable[i], sample.diagnostic_valid, sample.rx_enabled, now, wall);
        measure(&s->rx_status[i], sample.diagnostic_valid, sample.rx_status_raw, now, wall);
        if (optical_identity_qualified(s, i) && (s->identity[i][12] & 0x30) == 0x30) {
            fm10k_obt_power_sample power = {0};
            int power_rc = fm10k_obt_rx_power_read(s->bus, i + 1, &power);
            s->rx_power_not_ready[i] = power.not_ready;
            for (int lane = 0; lane < 12; ++lane)
                measure(&s->rx_power[i][lane], !power_rc && power.valid,
                        power.raw[lane], now, wall);
            if (power_rc) rc = power_rc;
        }
        s->obt_due[i] = now + SAMPLE_PERIOD_MS;
        ++s->samples;
        if (rc) ++s->io_errors;
        return rc;
    }
    for (int i = 0; i < 2; ++i) {
        if (now < s->identity_due[i]) continue;
        unsigned offset = s->identity_offset[i];
        size_t n = 128 - offset;
        if (n > 12) n = 12;
        int rc = fm10k_obt_identity_read(s->bus, i + 1, 128 + offset,
                                         s->identity_partial[i] + offset, n);
        if (rc) {
            s->identity_offset[i] = 0;
            s->identity_due[i] = now + IDENTITY_PERIOD_MS;
            s->identity_fresh[i] = false;
            ++s->io_errors;
            return rc;
        }
        s->identity_offset[i] += (unsigned)n;
        if (s->identity_offset[i] == 128) {
            memcpy(s->identity[i], s->identity_partial[i], 128);
            s->identity_valid[i] = true;
            s->identity_fresh[i] = true;
            s->identity_sample_ms[i] = now;
            s->identity_at[i] = wall;
            s->identity_offset[i] = 0;
            s->identity_due[i] = now + IDENTITY_PERIOD_MS;
        }
        return FM10K_OK;
    }
    return FM10K_OK;
}
int fm10k_monitor_shutdown(fm10k_monitor *s) {
    if (!s) return FM10K_INVALID;
    /* Normal LUT control survives owner shutdown without any bus traffic. */
    if (!s->fan.manual) return FM10K_OK;
    int rc = s->fan.curve_valid ? fm10k_fan_apply(s->bus, &s->fan.curve) : FM10K_IO;
    if (rc) (void)fm10k_fan_full(s->bus);
    s->fan.manual = false;
    s->fan.manual_deadline_ms = 0;
    s->fan.failsafe = rc != 0;
    return rc;
}

static int append(char *out, size_t size, size_t *offset, const char *format, ...) {
    if (*offset >= size) return FM10K_INVALID;
    va_list ap;
    va_start(ap, format);
    int n = vsnprintf(out + *offset, size - *offset, format, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= size - *offset) { *offset = size; return FM10K_INVALID; }
    *offset += (size_t)n;
    return FM10K_OK;
}
static void number(char out[40], const fm10k_measurement *m) {
    if (m->available) snprintf(out, 40, "%.6f", m->value);
    else snprintf(out, 40, "null");
}
static void identity_fields(const uint8_t raw[128], char *vendor, char part[13]) {
    char printable[129];
    for (int i = 0; i < 128; ++i)
        printable[i] = raw[i] >= 32 && raw[i] < 127 ? (char)raw[i] : ' ';
    printable[128] = 0;
    strcpy(vendor, strstr(printable, "FCI MergeOptics") ? "\"FCI / Amphenol\"" : "null");
    part[0] = 0;
    const char *p = strstr(printable, "10124588-");
    if (!p || strlen(p) < 12) return;
    for (int i = 9; i < 12; ++i)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'A' && p[i] <= 'Z'))) return;
    memcpy(part, p, 12); part[12] = 0;
}
int fm10k_monitor_format(const fm10k_monitor *s, uint64_t now, double wall,
                         char *out, size_t size) {
    if (!s || !out || !size || !isfinite(wall)) return FM10K_INVALID;
    size_t at = 0;
    append(out, size, &at, "{\"api\":1,\"profile\":\"%s\",\"board_hal\":\"%s\","
        "\"native_ready\":%s,\"native_generation\":\"%016llx\",\"native_commit\":\"%016llx\","
        "\"sensors\":{\"mode\":\"netlab\",\"quality\":\"%s\",\"sampled_at\":%.6f,\"temperatures\":[",
        nl_fm10k_profile_known(s->profile) ? s->profile : "unknown",
        s->native_bound ? "bound" : "unbound", s->native_ready ? "true" : "false",
        (unsigned long long)s->native_generation, (unsigned long long)s->native_commit,
        quality(&s->temperatures[0], now), s->temperatures[0].sampled_at);
    const char *ids[] = {"fm10840_core", "obt1", "obt2"};
    const char *labels[] = {"FM10840 核心", "OBT 1 内部", "OBT 2 内部"};
    for (int i = 0; i < 3; ++i) {
        char value[40]; number(value, &s->temperatures[i]);
        append(out, size, &at, "%s{\"id\":\"%s\",\"label\":\"%s\",\"celsius\":%s,"
            "\"source\":\"%s\",\"quality\":\"%s\",\"sampled_at\":%.6f}", i ? "," : "",
            ids[i], labels[i], value, i ? "FCI 0x16/0x17" : "LM96163 remote 0x01/0x10",
            quality(&s->temperatures[i], now), s->temperatures[i].sampled_at);
    }
    char pwm[40], tach[40], rpm[40], deadline[40];
    number(pwm, &s->pwm); number(tach, &s->tach);
    int rpm_value = fresh(&s->tach, now) && s->fan_readback.tach_valid ?
        fm10k_tach_rpm((uint16_t)s->tach.value, s->tach_factor) : -1;
    if (rpm_value >= 0) snprintf(rpm, sizeof(rpm), "%d", rpm_value);
    else strcpy(rpm, "null");
    if (s->fan.manual) snprintf(deadline, sizeof(deadline), "%.6f",
        wall + (s->fan.manual_deadline_ms > now ? (s->fan.manual_deadline_ms - now) / 1000.0 : 0));
    else strcpy(deadline, "null");
    const fm10k_fan_sample *raw = &s->fan_readback;
    char direct[24] = "null", shadow[24] = "null", config[24] = "null";
    if (raw->lm_tach_read) snprintf(direct, sizeof(direct), "%u", raw->lm_tach_count);
    if (raw->cpld_tach_read) snprintf(shadow, sizeof(shadow), "%u", raw->cpld_tach_count);
    if (raw->tach_configuration_valid) snprintf(config, sizeof(config), "%u", raw->tach_configuration);
    const char *diagnosis = !raw->lm_tach_read || !raw->tach_configuration_valid ? "read_failed" :
        !(raw->tach_configuration & 0x04) ? "tach_disabled" :
        raw->tach_configuration & 0x40 ? "controller_standby" :
        !raw->pwm_valid || (raw->pwm_mode & 0x08) ? "unsupported_clock" :
        !raw->tach_valid ? "no_signal" :
        !raw->cpld_tach_read ? "cpld_unavailable" :
        !raw->tach_shadow_matches ? "cpld_mismatch" : "ok";
    append(out, size, &at, "],\"fan\":{\"pwm_percent\":%s,\"pwm_quality\":\"%s\","
        "\"rpm\":%s,\"rpm_estimated\":true,\"tach_count\":%s,\"tach_factor\":%u,"
        "\"quality\":\"%s\",\"mode\":\"%s\",\"manual_expires_at\":%s,\"sampled_at\":%.6f,\"pwm_sampled_at\":%.6f,"
        "\"tach_source\":\"%s\",\"tach_controller_count\":%s,\"tach_cpld_count\":%s,"
        "\"tach_configuration\":%s,\"tach_diagnostic\":\"%s\",\"tach_assumed_pulses_per_revolution\":2}},\"optics\":[",
        pwm, quality(&s->pwm, now), rpm, tach, s->tach_factor,
        !fresh(&s->tach, now) ? quality(&s->tach, now) : rpm_value < 0 ? "invalid_tach" : "valid",
        s->fan.failsafe ? "failsafe" : s->fan.manual ? "manual" :
        s->fan.curve_valid ? "hardware_lut" : "unconfigured", deadline, s->tach.sampled_at, s->pwm.sampled_at,
        raw->tach_source == FM10K_TACH_CPLD ? "cpld" : raw->tach_source == FM10K_TACH_LM96163 ? "lm96163" : "unavailable",
        direct, shadow, config, diagnosis);
    for (int i = 0; i < 2; ++i) {
        char tx[40], vendor[32], part[13], tx_cdr[40], rx_cdr[40], rx_enable[40], rx_status[40];
        number(tx, &s->tx[i]);
        number(tx_cdr, &s->tx_cdr[i]); number(rx_cdr, &s->rx_cdr[i]);
        number(rx_enable, &s->rx_enable[i]); number(rx_status, &s->rx_status[i]);
        identity_fields(s->identity[i], vendor, part);
        append(out, size, &at, "%s{\"mpo\":%d,\"vendor\":%s,\"part_number\":%s%s%s,"
            "\"identity_quality\":\"%s\",\"identity_sampled_at\":%.6f,\"tx_enable_mask\":%s,"
            "\"quality\":\"%s\",\"sampled_at\":%.6f,"
            "\"diagnostics\":{\"tx_cdr_raw\":%s,\"rx_cdr_raw\":%s,\"rx_enable_mask\":%s,\"rx_status_07_08_raw\":%s,"
            "\"quality\":\"%s\",\"sampled_at\":%.6f,\"status_interpretation\":\"unqualified\"},",
            i ? "," : "", i + 1, vendor, part[0] ? "\"" : "", part[0] ? part : "null", part[0] ? "\"" : "",
            !s->identity_valid[i] ? "unavailable" : s->identity_fresh[i] &&
            now >= s->identity_sample_ms[i] && now - s->identity_sample_ms[i] < 120000 ? "valid" : "stale",
            s->identity_at[i], tx, quality(&s->tx[i], now), s->tx[i].sampled_at,
            tx_cdr, rx_cdr, rx_enable, rx_status, quality(&s->rx_status[i], now), s->rx_status[i].sampled_at);
        char identity_hex[193];
        unsigned identity_sum = 0;
        for (int n = 0; n < 96; ++n) {
            snprintf(identity_hex + n * 2, 3, "%02x", s->identity[i][n]);
            if (n < 95) identity_sum += s->identity[i][n];
        }
        append(out, size, &at, "\"identity_page0_128_223_hex\":\"%s\",\"identity_checksum_ok\":%s,",
               identity_hex, s->identity_valid[i] && (identity_sum & 255) == s->identity[i][95] ? "true" : "false");
        bool qualified = optical_identity_qualified(s, i);
        bool average = qualified && (s->identity[i][12] & 0x30) == 0x30;
        bool identity_current = s->identity_fresh[i] && now >= s->identity_sample_ms[i] &&
                                now - s->identity_sample_ms[i] < 120000;
        const fm10k_measurement *power = &s->rx_power[i][0];
        const char *power_quality = !qualified ? "unqualified" : !average ? "unsupported_format" :
            !identity_current ? "stale" : s->rx_power_not_ready[i] ? "not_ready" : quality(power, now);
        append(out, size, &at, "\"tx_power\":null,\"tx_power_quality\":\"%s\","
            "\"rx_power_quality\":\"%s\",\"rx_power_sampled_at\":%.6f,\"rx_power\":",
            !qualified ? "unqualified" : (s->identity[i][12] & 0x40) ? "not_exposed" : "unsupported",
            power_quality, power->sampled_at);
        if (!average || !power->available) append(out, size, &at, "null");
        else {
            append(out, size, &at, "[");
            for (int lane = 0; lane < 12; ++lane) {
                unsigned value = (unsigned)s->rx_power[i][lane].value;
                char dbm[40] = "null";
                if (value) snprintf(dbm, sizeof(dbm), "%.6f", 10.0 * log10(value / 10000.0));
                append(out, size, &at, "%s{\"channel\":%d,\"raw\":%u,\"microwatts\":%.1f,\"dbm\":%s}",
                       lane ? "," : "", lane, value, value / 10.0, dbm);
            }
            append(out, size, &at, "]");
        }
        append(out, size, &at, ",\"power_source\":\"cxp-rx-page1\",\"power_format\":\"average\","
            "\"power_resolution_uw\":0.1,\"power_spec_tolerance_db\":3}");
    }
    append(out, size, &at, "],\"sample_count\":%llu,\"io_errors\":%llu}",
        (unsigned long long)s->samples, (unsigned long long)s->io_errors);
    return at < size ? (int)at : FM10K_INVALID;
}
