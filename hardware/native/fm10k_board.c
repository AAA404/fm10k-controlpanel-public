#include "fm10k_board.h"
#include <string.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>

static int read8(fm10k_bus *b, uint8_t a, int r, uint8_t *v) {
    return b && b->read ? b->read(b->context, a, r, v, 1) : FM10K_IO;
}
static int write8(fm10k_bus *b, uint8_t a, int r, uint8_t v) {
    return b && b->write ? b->write(b->context, a, r, &v, 1) : FM10K_IO;
}
static int select_mux(fm10k_bus *b, uint8_t mux, uint8_t *previous) {
    uint8_t check;
    if (!b || !b->read || !b->write || (!!b->enter != !!b->leave))
        return FM10K_INVALID;
    if (b->enter && b->enter(b->context)) {
        fprintf(stderr, "FM10840 board: I2C ownership/lock unavailable\n");
        return FM10K_IO;
    }
    if (read8(b, 0x58, -1, previous)) {
        fprintf(stderr, "FM10840 board: mux 0x58 read failed\n");
        goto fail;
    }
    /* PCA9545's upper nibble is read-only interrupt status. */
    *previous &= 15;
    if (!write8(b, 0x58, -1, mux) &&
        !read8(b, 0x58, -1, &check) && (check & 15) == mux)
        return FM10K_OK;
    fprintf(stderr, "FM10840 board: mux 0x58 selection 0x%02x failed\n", mux);
    (void)write8(b, 0x58, -1, *previous);
fail:
    if (b->leave) (void)b->leave(b->context);
    return FM10K_IO;
}
static int restore_mux(fm10k_bus *b, uint8_t previous, int result) {
    uint8_t check;
    if (write8(b, 0x58, -1, previous) ||
        read8(b, 0x58, -1, &check) || (check & 15) != previous)
        result = FM10K_IO;
    if (b->leave && b->leave(b->context)) result = FM10K_IO;
    return result;
}
static int round_even(int numerator, int denominator) {
    int q = numerator / denominator, r = numerator % denominator;
    return q + (2 * r > denominator || (2 * r == denominator && q % 2));
}
int fm10k_group_index(int epl) {
    return nl_fm10k_group_index(epl);
}
int fm10k_group_validate(const fm10k_group *g) {
    return nl_fm10k_group_valid(g) ? FM10K_OK : FM10K_INVALID;
}
bool fm10k_group_equal(const fm10k_group *a, const fm10k_group *b) {
    /* Remembered split preferences do not describe an aggregate's live PHY. */
    return nl_fm10k_group_equal(a, b);
}
uint16_t fm10k_group_tx_mask(const fm10k_group *g) {
    if (fm10k_group_validate(g)) return 0;
    int shift = (fm10k_group_index(g->epl) % 3) * 4;
    return (uint16_t)((g->mode ? (g->enabled ? 15 : 0) : g->enabled) << shift);
}
int fm10k_tx_read(fm10k_bus *b, int mpo, uint16_t *out) {
    uint8_t mux, high, low;
    if (!out || (mpo != 1 && mpo != 2)) return FM10K_INVALID;
    if (select_mux(b, (uint8_t)(1 << (mpo - 1)), &mux)) return FM10K_IO;
    int rc = read8(b, 0x50, 56, &high) || read8(b, 0x50, 57, &low);
    if (!rc) *out = (uint16_t)(((high & 15) << 8) | low);
    return restore_mux(b, mux, rc ? FM10K_IO : FM10K_OK);
}
static int write_retry(fm10k_bus *b, uint8_t address, uint8_t reg, uint8_t target) {
    uint8_t actual;
    for (int i = 0; i <= 12; ++i) {
        if (read8(b, address, reg, &actual)) return FM10K_IO;
        if (actual == target) return FM10K_OK;
        if (i == 12 || write8(b, address, reg, target)) return FM10K_IO;
    }
    return FM10K_IO;
}
int fm10k_tx_update(fm10k_bus *b, int mpo, uint16_t lanes, uint16_t enabled) {
    uint8_t mux, high, low, check_high, check_low;
    if ((mpo != 1 && mpo != 2) || lanes > 0xfff || (enabled & ~lanes))
        return FM10K_INVALID;
    if (select_mux(b, (uint8_t)(1 << (mpo - 1)), &mux)) return FM10K_IO;
    int rc = FM10K_IO;
    if (read8(b, 0x50, 56, &high) || read8(b, 0x50, 57, &low)) goto done;
    uint16_t current = (uint16_t)(((high & 15) << 8) | low);
    uint16_t target = (uint16_t)((current & ~lanes) | enabled);
    /* Offset 56 is HIGH nibble, 57 LOW byte; preserve reserved high bits. */
    high = (uint8_t)((high & 0xf0) | (target >> 8));
    if (write_retry(b, 0x50, 56, high) ||
        write_retry(b, 0x50, 57, (uint8_t)target)) goto done;
    if (read8(b, 0x50, 56, &check_high) || read8(b, 0x50, 57, &check_low)) goto done;
    if (check_high == high && check_low == (uint8_t)target) rc = FM10K_OK;
done:
    return restore_mux(b, mux, rc);
}

typedef struct { uint8_t address, reg, value; } obt_setting;
/* Values match the locked IES 4.3.2 platform defaults and fci_a11_v01.conf.
 * Parameter data only; the original SDK routines hardcode logical 1 and 4,
 * which no longer identify distinct optical engines in a 24-slot model. */
static const obt_setting obt_settings[FM10K_OBT_SETUP_REGISTERS] = {
    {0x50, 68, 255}, {0x50, 69, 255}, {0x50, 70, 255},
    {0x50, 71, 255}, {0x50, 72, 255}, {0x50, 73, 255}, {0x50, 43, 1},
    {0x40, 62, 238}, {0x40, 63, 238}, {0x40, 64, 238},
    {0x40, 65, 238}, {0x40, 66, 238}, {0x40, 67, 238},
    {0x40, 68, 0}, {0x40, 69, 0}, {0x40, 70, 0},
    {0x40, 71, 0}, {0x40, 72, 0}, {0x40, 73, 0}, {0x40, 43, 0},
    {0x40, 56, 15}, {0x40, 57, 255},
};
static int obt_write_verified(fm10k_bus *b, const obt_setting *s, uint8_t target) {
    uint8_t actual;
    for (int attempt = 0; attempt <= 12; ++attempt) {
        if (read8(b, s->address, s->reg, &actual)) return FM10K_IO;
        if (actual == target) return FM10K_OK;
        if (attempt == 12 || write8(b, s->address, s->reg, target)) return FM10K_IO;
        if (b->delay_ms) b->delay_ms(b->context, 30);
    }
    return FM10K_IO;
}
int fm10k_obt_setup(fm10k_bus *b, int mpo, fm10k_obt_setup_report *out) {
    uint8_t mux, high, low, target[FM10K_OBT_SETUP_REGISTERS];
    bool attempted[FM10K_OBT_SETUP_REGISTERS] = {false};
    int rc = FM10K_IO;
    if (!out || (mpo != 1 && mpo != 2)) return FM10K_INVALID;
    memset(out, 0, sizeof(*out));
    out->failed_address = out->failed_register = -1;
    if (select_mux(b, (uint8_t)mpo, &mux)) return FM10K_IO;
    if (read8(b, 0x50, 56, &high) || read8(b, 0x50, 57, &low)) goto done;
    if ((high & 15) || low) { rc = FM10K_INVALID; goto done; }
    /* Capture the whole before-image before any tuning write. */
    for (int i = 0; i < FM10K_OBT_SETUP_REGISTERS; ++i) {
        const obt_setting *s = &obt_settings[i];
        if (read8(b, s->address, s->reg, &out->before[i])) {
            out->failed_address = s->address; out->failed_register = s->reg;
            goto done;
        }
        target[i] = s->value;
        if (s->address == 0x40 && s->reg == 56)
            target[i] |= out->before[i] & 0xf0;
    }
    out->captured = true;
    for (int i = 0; i < FM10K_OBT_SETUP_REGISTERS; ++i) {
        if (out->before[i] == target[i]) continue;
        const obt_setting *s = &obt_settings[i];
        ++out->changed;
        attempted[i] = true; /* An error may be returned after a write latched. */
        if (obt_write_verified(b, s, target[i])) {
            out->failed_address = s->address; out->failed_register = s->reg;
            goto rollback;
        }
    }
    for (int i = 0; i < FM10K_OBT_SETUP_REGISTERS; ++i) {
        const obt_setting *s = &obt_settings[i];
        if (read8(b, s->address, s->reg, &out->after[i]) || out->after[i] != target[i]) {
            out->failed_address = s->address; out->failed_register = s->reg;
            goto rollback;
        }
    }
    /* Tuning must never enable a laser; normal admin/TX transactions do that. */
    if (read8(b, 0x50, 56, &high) || read8(b, 0x50, 57, &low) || (high & 15) || low)
        goto rollback;
    rc = FM10K_OK;
    goto done;
rollback:
    out->restored = true;
    for (int i = FM10K_OBT_SETUP_REGISTERS - 1; i >= 0; --i)
        if (attempted[i] && obt_write_verified(b, &obt_settings[i], out->before[i]))
            out->restored = false;
    rc = out->restored ? FM10K_IO : FM10K_ROLLBACK_FAILED;
done:
    rc = restore_mux(b, mux, rc);
    out->verified = rc == FM10K_OK;
    return rc;
}

int fm10k_fan_read(fm10k_bus *b, fm10k_fan_sample *out) {
    uint8_t mux, high, low, check;
    if (!out) return FM10K_INVALID;
    memset(out, 0, sizeof(*out));
    if (select_mux(b, 8, &mux)) return FM10K_IO;
    for (int i = 0; i < 3; ++i) {
        if (read8(b, 0x4c, 0x01, &high) ||
            read8(b, 0x4c, 0x10, &low) ||
            read8(b, 0x4c, 0x01, &check)) break;
        if (high != check) continue;
        out->core_c = (double)(int8_t)high + (low & 0xe0) / 256.0;
        out->core_valid = out->core_c >= -40 && out->core_c < 127;
        break;
    }
    out->pwm_valid = !read8(b, 0x4c, 0x4a, &out->pwm_mode) &&
                     !read8(b, 0x4c, 0x4c, &out->pwm);
    out->tach_configuration_valid = !read8(b, 0x4c, 0x03, &out->tach_configuration);
    /* Reading LM96163 LSB latches its MSB (SNAS433D p29). This is the
     * authoritative counter; a CPLD shadow is usable only when corroborated.
     * Single-byte CPLD accesses have returned the address bytes themselves
     * on A11, previously exposing 0xa4a3 as an apparently valid 128 RPM. */
    if (!read8(b, 0x4c, 0x46, &low) && !read8(b, 0x4c, 0x47, &high)) {
        out->lm_tach_count = (uint16_t)((high << 8) | low);
        out->lm_tach_read = true;
    }
    /* Match the reference board's five-byte memory-handler read. A burst
     * avoids the suspect single-byte path; matching pairs reject a torn
     * asynchronous CPLD refresh. No controller/PWM register is written. */
    for (int i = 0; i < 3; ++i) {
        uint8_t first[5], second[5];
        if (b->read(b->context, 0x59, 0xa0, first, sizeof(first)) ||
            b->read(b->context, 0x59, 0xa0, second, sizeof(second))) break;
        if (first[3] != second[3] || first[4] != second[4]) continue;
        out->cpld_tach_count = (uint16_t)((first[4] << 8) | first[3]);
        out->cpld_tach_read = true;
        break;
    }
    out->tach_read = out->lm_tach_read;
    out->tach_count = out->lm_tach_count;
    out->tach_source = out->lm_tach_read ? FM10K_TACH_LM96163 : FM10K_TACH_NONE;
    out->tach_valid = out->lm_tach_read && out->tach_configuration_valid &&
        (out->tach_configuration & 0x04) && !(out->tach_configuration & 0x40) &&
        out->pwm_valid && !(out->pwm_mode & 0x08) &&
        out->lm_tach_count && out->lm_tach_count != 0xffff;
    if (out->tach_valid && out->cpld_tach_read && out->cpld_tach_count && out->cpld_tach_count != 0xffff) {
        unsigned difference = out->cpld_tach_count > out->lm_tach_count ?
            out->cpld_tach_count - out->lm_tach_count : out->lm_tach_count - out->cpld_tach_count;
        /* Cache refresh can lag a changing fan. Prefer the direct counter
         * when the periods differ by more than 25%, with a 4-count margin. */
        out->tach_shadow_matches = difference * 4U <= (unsigned)out->lm_tach_count + 16U;
        if (out->tach_shadow_matches) {
            out->tach_count = out->cpld_tach_count;
            out->tach_source = FM10K_TACH_CPLD;
        }
    }
    int rc = restore_mux(b, mux, FM10K_OK);
    if (rc) { memset(out, 0, sizeof(*out)); return rc; }
    return out->core_valid && out->pwm_valid && out->tach_read ? FM10K_OK : FM10K_IO;
}

int fm10k_obt_read(fm10k_bus *b, int mpo, fm10k_obt_sample *out) {
    uint8_t mux, high, low, check;
    if (!out || (mpo != 1 && mpo != 2)) return FM10K_INVALID;
    memset(out, 0, sizeof(*out));
    if (select_mux(b, (uint8_t)mpo, &mux)) return FM10K_IO;
    for (int i = 0; i < 3; ++i) {
        if (read8(b, 0x50, 0x16, &high) || read8(b, 0x50, 0x17, &low) ||
            read8(b, 0x50, 0x16, &check)) break;
        if (high != check) continue;
        out->temperature_c = (double)(int16_t)((high << 8) | low) / 256.0;
        out->temperature_valid = out->temperature_c >= -40 && out->temperature_c < 127;
        break;
    }
    if (!read8(b, 0x50, 56, &high) && !read8(b, 0x50, 57, &low)) {
        out->tx_enabled = (uint16_t)(((high & 15) << 8) | low);
        out->tx_valid = true;
    }
    uint8_t rx_high, rx_low, status_high, status_low;
    if (!read8(b, 0x50, 43, &out->tx_cdr) &&
        !read8(b, 0x40, 43, &out->rx_cdr) &&
        !read8(b, 0x40, 56, &rx_high) && !read8(b, 0x40, 57, &rx_low) &&
        !read8(b, 0x40, 7, &status_high) && !read8(b, 0x40, 8, &status_low)) {
        out->rx_enabled = (uint16_t)(((rx_high & 15) << 8) | rx_low);
        out->rx_status_raw = (uint16_t)((status_high << 8) | status_low);
        out->diagnostic_valid = true;
    }
    int rc = restore_mux(b, mux, FM10K_OK);
    if (rc) { memset(out, 0, sizeof(*out)); return rc; }
    return out->temperature_valid && out->tx_valid ? FM10K_OK : FM10K_IO;
}

int fm10k_obt_rx_power_read(fm10k_bus *b, int mpo, fm10k_obt_power_sample *out) {
    uint8_t mux, page = 0, check, status, data[24];
    bool saved = false;
    int rc = FM10K_IO;
    if (!out || !b || !b->delay_ms || (mpo != 1 && mpo != 2)) return FM10K_INVALID;
    memset(out, 0, sizeof(*out));
    if (select_mux(b, (uint8_t)mpo, &mux)) return FM10K_IO;
    if (read8(b, 0x40, 2, &status)) goto done;
    if (status & 1) { out->not_ready = true; rc = FM10K_OK; goto done; }
    if (read8(b, 0x40, 127, &page)) goto done;
    saved = true;
    if (page != 1) {
        if (write8(b, 0x40, 127, 1)) goto done;
        b->delay_ms(b->context, 30);
    }
    if (read8(b, 0x40, 127, &check) || check != 1 ||
        b->read(b->context, 0x40, 206, data, 12) ||
        b->read(b->context, 0x40, 218, data + 12, 12) ||
        read8(b, 0x40, 127, &check) || check != 1 ||
        read8(b, 0x40, 2, &status)) goto done;
    out->not_ready = (status & 1) != 0;
    rc = FM10K_OK;
done:
    /* A failed write may still have taken effect: always restore the saved
     * selector, including when selecting page 1 returned an error. */
    if (saved && page != 1) {
        if (write8(b, 0x40, 127, page)) rc = FM10K_IO;
        b->delay_ms(b->context, 30);
        if (read8(b, 0x40, 127, &check) || check != page) rc = FM10K_IO;
    }
    rc = restore_mux(b, mux, rc);
    if (!rc && saved && !out->not_ready) {
        /* CXP table 27: lower address is MSB; channel 11 precedes 0. */
        for (int lane = 0; lane < 12; ++lane) {
            int offset = (11 - lane) * 2;
            out->raw[lane] = (uint16_t)((data[offset] << 8) | data[offset + 1]);
        }
        out->valid = true;
    }
    return rc;
}

int fm10k_obt_identity_read(fm10k_bus *b, int mpo, unsigned offset,
                           uint8_t *out, size_t n) {
    uint8_t mux, page, check, data[12];
    int rc = FM10K_IO;
    bool page_saved = false;
    if (!out || (mpo != 1 && mpo != 2) || offset < 128 || offset > 255 ||
        !n || n > sizeof(data) || n > 256 - offset) return FM10K_INVALID;
    if (select_mux(b, (uint8_t)mpo, &mux)) return FM10K_IO;
    if (read8(b, 0x50, 0x7f, &page)) goto done;
    page_saved = true;
    if (page) {
        if (!b->delay_ms || write8(b, 0x50, 0x7f, 0)) goto done;
        b->delay_ms(b->context, 30);
        if (read8(b, 0x50, 0x7f, &check) || check != 0) goto done;
    }
    if (b->read(b->context, 0x50, (int)offset, data, n)) goto done;
    rc = FM10K_OK;
done:
    if (page_saved && page) {
        if (write8(b, 0x50, 0x7f, page)) rc = FM10K_IO;
        if (b->delay_ms) b->delay_ms(b->context, 30);
        if (read8(b, 0x50, 0x7f, &check) || check != page) rc = FM10K_IO;
    }
    rc = restore_mux(b, mux, rc);
    if (!rc) memcpy(out, data, n);
    return rc;
}
int fm10k_fan_validate(const fm10k_fan_curve *f) {
    return nl_fm10k_fan_valid(f) ? FM10K_OK : FM10K_INVALID;
}
int fm10k_fan_lut(const fm10k_fan_curve *f, fm10k_lut_point out[12]) {
    if (!out || fm10k_fan_validate(f)) return FM10K_INVALID;
    out[0] = (fm10k_lut_point){0, (uint8_t)round_even(f->idle_pwm * 255, 100)};
    for (int i = 0; i < 9; ++i) {
        int percent = round_even(f->idle_pwm * 8 + (f->load_pwm - f->idle_pwm) * i, 8);
        out[i + 1] = (fm10k_lut_point){
            (uint8_t)round_even(f->idle_c * 8 + (f->load_c - f->idle_c) * i, 8),
            (uint8_t)round_even(percent * 255, 100)};
    }
    out[10] = (fm10k_lut_point){(uint8_t)f->critical_c, 255};
    out[11] = (fm10k_lut_point){127, 255};
    return FM10K_OK;
}
bool fm10k_fan_curve_equal(const fm10k_fan_curve *a, const fm10k_fan_curve *b) {
    return nl_fm10k_fan_equal(a, b);
}
static const uint8_t fan_registers[FM10K_FAN_IMAGE_BYTES] = {
    0x30, 0x4b, 0x4d, 0x45, 0x4e, 0x4f, 0x03, 0x19, 0x21,
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b,
    0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
    0x4a, 0x4c
};
int fm10k_fan_image_read(fm10k_bus *b, fm10k_fan_image *out) {
    uint8_t mux;
    fm10k_fan_image image = {{0}};
    if (!out) return FM10K_INVALID;
    if (select_mux(b, 8, &mux)) return FM10K_IO;
    int rc = FM10K_OK;
    for (unsigned i = 0; i < FM10K_FAN_IMAGE_BYTES; ++i)
        if (read8(b, 0x4c, fan_registers[i], &image.values[i])) { rc = FM10K_IO; break; }
    rc = restore_mux(b, mux, rc);
    if (!rc) *out = image;
    return rc;
}
bool fm10k_fan_image_matches(const fm10k_fan_image *image, const fm10k_fan_curve *f) {
    if (!image) return false;
    const uint8_t *v = image->values;
    bool full = v[33] == 0x30 && v[34] == 255;
    if (!f) return full;
    fm10k_lut_point lut[12];
    if (fm10k_fan_lut(f, lut)) return false;
    int response = f->response_milliseconds == 5450 ? 0x11 :
        f->response_milliseconds == 10900 ? 0x13 : f->response_milliseconds == 21600 ? 0x15 : 0x17;
    if (v[0] != 0x02 || v[1] != 0x3f || v[2] != 0x08 || v[3] != response ||
        v[4] != 0 || v[5] != f->hysteresis_c || v[6] != 0x06 ||
        v[7] != f->critical_c || v[8] != f->hysteresis_c || (v[33] != 0x10 && !full))
        return false;
    for (int i = 0; i < 12; ++i)
        if (v[9 + 2 * i] != lut[i].celsius || v[10 + 2 * i] != lut[i].pwm) return false;
    return true;
}
bool fm10k_fan_snapshot_equal(const fm10k_fan_snapshot *a, const fm10k_fan_snapshot *b) {
    if (!a || !b || !a->valid || !b->valid || a->curve_valid != b->curve_valid ||
        (a->curve_valid && !fm10k_fan_curve_equal(&a->curve, &b->curve)) ||
        !fm10k_fan_image_matches(&a->image, a->curve_valid ? &a->curve : NULL) ||
        !fm10k_fan_image_matches(&b->image, b->curve_valid ? &b->curve : NULL)) return false;
    /* LUT output and the safety override are operational state. All 33
     * programmed control bytes must match; protection may still demand full
     * speed after the same configuration has been restored. */
    return memcmp(a->image.values, b->image.values, 33) == 0;
}
static int write_verified(fm10k_bus *b, uint8_t reg, uint8_t value) {
    uint8_t actual = 0;
    int written = write8(b, 0x4c, reg, value);
    int read = written ? FM10K_IO : read8(b, 0x4c, reg, &actual);
    if (written || read || actual != value) {
        fprintf(stderr, "FM10840 fan: register=0x%02x expected=0x%02x actual=0x%02x write=%d read=%d\n",
                reg, value, actual, written, read);
        return FM10K_IO;
    }
    return FM10K_OK;
}
static int full_selected(fm10k_bus *b) {
    int mode = write_verified(b, 0x4a, 0x30);
    int pwm = write_verified(b, 0x4c, 0xff);
    return mode || pwm ? FM10K_IO : FM10K_OK;
}
int fm10k_fan_bootstrap(fm10k_bus *b) {
    uint8_t previous, status;
    int rc = FM10K_IO;
    if (select_mux(b, 8, &previous)) return FM10K_IO;
    /* LM96163 SNAS433D, pp.21/36: initialize the fan registers in order.
     * POR uses six-bit PWM; 0xff cannot read back until 22.5 kHz and PHR
     * are enabled. A previous process's fan setup cannot be assumed. */
    for (int attempt = 0; ; ++attempt) {
        if (read8(b, 0x4c, 0x33, &status)) goto out;
        if (!(status & 0x80)) break;
        if (attempt == 12) goto out;
        if (b->delay_ms) b->delay_ms(b->context, 30);
    }
    const uint8_t initial[][2] = {
        {0x30, 0x02}, {0x4a, 0x30}, {0x4b, 0x3f},
        {0x4d, 0x08}, {0x45, 0x10},
    };
    for (size_t i = 0; i < sizeof(initial) / sizeof(initial[0]); ++i) {
        if (write_verified(b, initial[i][0], initial[i][1])) {
            (void)full_selected(b);
            goto out;
        }
    }
    if (write8(b, 0x4c, 0x4c, 0xff)) goto failed_pwm;
    /* During the documented 3.2 s spin-up interval, 4C reads zero even
     * though the fan is driven at full speed. Write once, then poll; repeated
     * writes must not restart spin-up. Other mismatches still fail closed. */
    for (int attempt = 0; ; ++attempt) {
        uint8_t actual;
        if (read8(b, 0x4c, 0x4c, &actual)) goto failed_pwm;
        if (actual == 0xff) { rc = FM10K_OK; break; }
        if (actual != 0 || attempt == 150) goto failed_pwm;
        if (b->delay_ms) b->delay_ms(b->context, 30);
    }
    goto out;
failed_pwm:
    fprintf(stderr, "FM10840 fan: startup full-speed PWM verification failed\n");
    (void)full_selected(b);
out:
    return restore_mux(b, previous, rc);
}
int fm10k_fan_full(fm10k_bus *b) {
    uint8_t previous;
    if (select_mux(b, 8, &previous)) return FM10K_IO;
    return restore_mux(b, previous, full_selected(b));
}
int fm10k_fan_image_restore(fm10k_bus *b, const fm10k_fan_image *image,
                             const fm10k_fan_curve *curve, bool full_speed) {
    uint8_t mux;
    if (!fm10k_fan_image_matches(image, curve)) return FM10K_INVALID;
    if (select_mux(b, 8, &mux)) return FM10K_IO;
    if (full_selected(b)) goto fail;
    for (int i = 0; i < 33; ++i)
        if (write_verified(b, fan_registers[i], image->values[i])) goto fail;
    if (curve && !full_speed && write_verified(b, 0x4a, 0x10)) goto fail;
    return restore_mux(b, mux, FM10K_OK);
fail:
    (void)full_selected(b);
    return restore_mux(b, mux, FM10K_IO);
}
int fm10k_fan_configure(fm10k_bus *b, const fm10k_fan_curve *f, bool full_speed) {
    fm10k_lut_point lut[12];
    uint8_t previous;
    if (fm10k_fan_lut(f, lut)) return FM10K_INVALID;
    if (select_mux(b, 8, &previous)) return FM10K_IO;
    int response = f->response_milliseconds == 5450 ? 0x11 :
        f->response_milliseconds == 10900 ? 0x13 :
        f->response_milliseconds == 21600 ? 0x15 : 0x17;
    if (full_selected(b)) goto fail;
    const uint8_t initial[][2] = {{0x30, 0x02}, {0x4b, 0x3f},
        {0x4d, 0x08}, {0x45, (uint8_t)response},
        {0x4e, 0}, {0x4f, (uint8_t)f->hysteresis_c}};
    for (size_t i = 0; i < sizeof(initial) / sizeof(initial[0]); ++i)
        if (write_verified(b, initial[i][0], initial[i][1])) goto fail;
    for (int i = 0; i < 12; ++i)
        if (write_verified(b, (uint8_t)(0x50 + i * 2), lut[i].celsius) ||
            write_verified(b, (uint8_t)(0x51 + i * 2), lut[i].pwm)) goto fail;
    if (write_verified(b, 0x03, 0x06) ||
        write_verified(b, 0x19, (uint8_t)f->critical_c) ||
        write_verified(b, 0x21, (uint8_t)f->hysteresis_c) ||
        (!full_speed && write_verified(b, 0x4a, 0x10))) goto fail;
    return restore_mux(b, previous, FM10K_OK);
fail:
    (void)full_selected(b);
    return restore_mux(b, previous, FM10K_IO);
}
int fm10k_fan_apply(fm10k_bus *b, const fm10k_fan_curve *f) {
    return fm10k_fan_configure(b, f, false);
}
int fm10k_tach_rpm(uint16_t count, uint32_t factor) {
    return count == 0 || count == 65535 || !factor || factor > INT_MAX ? -1 :
        round_even((int)factor, count);
}
int fm10k_fan_manual(fm10k_bus *b, fm10k_fan_state *s, int pwm, int seconds,
                     uint64_t now, bool valid, double core) {
    uint8_t mux;
    if (!s || !s->curve_valid || !valid || !isfinite(core) || fm10k_fan_validate(&s->curve) ||
        pwm < 25 || pwm > 100 || seconds < 1 || seconds > 60) return FM10K_INVALID;
    if (core >= s->curve.critical_c) pwm = 100;
    if (select_mux(b, 8, &mux)) return FM10K_IO;
    int rc = write_verified(b, 0x4a, 0x30) ||
        write_verified(b, 0x4c, (uint8_t)round_even(pwm * 255, 100));
    if (rc) (void)full_selected(b);
    rc = restore_mux(b, mux, rc ? FM10K_IO : FM10K_OK);
    if (!rc) {
        s->manual = true;
        s->manual_deadline_ms = now + (uint64_t)seconds * 1000;
    } else {
        /* The write may have changed manual mode before failing. A later
         * tick must reconcile it, even if the caller receives an error. */
        s->manual = false;
        s->manual_deadline_ms = 0;
        s->failsafe = true;
    }
    return rc;
}
int fm10k_fan_tick(fm10k_bus *b, fm10k_fan_state *s, uint64_t now,
                   bool valid, double core) {
    if (!s || !s->curve_valid) return fm10k_fan_full(b);
    if (!valid || !isfinite(core) || core >= s->curve.critical_c) {
        s->failsafe = true;
        s->manual = false;
        s->manual_deadline_ms = 0;
        return fm10k_fan_full(b);
    }
    if (s->failsafe && core > s->curve.critical_c - s->curve.hysteresis_c)
        return fm10k_fan_full(b);
    if (s->failsafe || (s->manual && now >= s->manual_deadline_ms)) {
        int rc = fm10k_fan_apply(b, &s->curve);
        if (!rc) { s->manual = false; s->failsafe = false; s->manual_deadline_ms = 0; }
        else { s->manual = false; s->failsafe = true; s->manual_deadline_ms = 0; }
        return rc;
    }
    return FM10K_OK;
}
static int apply_modes(fm10k_bus *b, const fm10k_group_ops *ops,
                        const fm10k_group *g, uint16_t mask) {
    int mpo = fm10k_group_index(g->epl) / 3 + 1;
    if (fm10k_tx_update(b, mpo, mask, 0) ||
        ops->disable(ops->context, g->epl) ||
        ops->set_modes(ops->context, g) ||
        fm10k_tx_update(b, mpo, mask, fm10k_group_tx_mask(g)) ||
        ops->restore_ports(ops->context, g) ||
        ops->verify(ops->context, g)) return FM10K_IO;
    return FM10K_OK;
}
int fm10k_group_apply(fm10k_bus *b, const fm10k_group_ops *ops,
                       const fm10k_group *target) {
    fm10k_group before = {0};
    if (fm10k_group_validate(target) || !ops || !ops->capture || !ops->quiesce ||
        !ops->disable || !ops->set_modes || !ops->restore_ports || !ops->verify ||
        !ops->degraded) return FM10K_INVALID;
    int index = fm10k_group_index(target->epl), mpo = index / 3 + 1;
    uint16_t mask = (uint16_t)(15 << (index % 3 * 4)), before_tx;
    if (ops->capture(ops->context, target->epl, &before) ||
        fm10k_group_validate(&before) || before.epl != target->epl ||
        fm10k_tx_read(b, mpo, &before_tx) ||
        (before_tx & mask) != fm10k_group_tx_mask(&before)) return FM10K_IO;
    if (ops->quiesce(ops->context, target->epl, true)) {
        /* A pause error can follow partial protocol suspension. */
        if (!ops->quiesce(ops->context, target->epl, false)) return FM10K_IO;
        (void)fm10k_tx_update(b, mpo, mask, 0);
        (void)ops->disable(ops->context, target->epl);
        ops->degraded(ops->context, target->epl);
        return FM10K_ROLLBACK_FAILED;
    }
    if (!apply_modes(b, ops, target, mask) &&
        !ops->quiesce(ops->context, target->epl, false)) return FM10K_OK;
    /* Hardware before-image, not desired configuration, is restored. Never
     * touch an EPL outside this mask, even if compensation also fails. */
    if (ops->quiesce(ops->context, target->epl, true) ||
        apply_modes(b, ops, &before, mask) ||
        fm10k_tx_update(b, mpo, mask, before_tx & mask) ||
        ops->quiesce(ops->context, target->epl, false)) {
        (void)fm10k_tx_update(b, mpo, mask, 0);
        (void)ops->disable(ops->context, target->epl);
        ops->degraded(ops->context, target->epl);
        return FM10K_ROLLBACK_FAILED;
    }
    return FM10K_IO;
}
