/* Included by the pinned port adapter. The transaction's historical byte
 * field represents this EPL's four disable bits. Physical FCI writes remain
 * 12-bit enable-mask operations at decimal offsets 56/57, never byte 86. */
typedef struct {
    int resource, epl, mpo, shift, base, lane;
    int sdk_index[4];
    bool aggregate;
    fm_byte lane_mask;
    fm_uint64 fingerprint;
} fci_port_topology;

static fm10k_sdk_bus fci_bus;

static fm_status fci_prepare(fm_int sw) {
    if (!fci_bus.attached && fm10k_sdk_bus_attach(&fci_bus, sw))
        return FM_ERR_UNINITIALIZED;
    return fci_bus.sw == sw && pthread_equal(fci_bus.owner, pthread_self()) &&
           !fci_bus.faulted ? FM_OK : FM_ERR_INVALID_ARGUMENT;
}
static fm_status fci_fixed_topology(fm_int sw, fm_int port, fci_port_topology *out) {
    static const int epls[6] = {0, 1, 2, 5, 6, 7};
    nl_port_entry entries[NL_MAX_PORTS_PER_PROFILE];
    bool seen[24] = {false};
    int count;
    if (!out || sw != 0 || port < 1 || port > 24) return FM_ERR_INVALID_PORT;
    fm_status status = fci_prepare(sw);
    if (status != FM_OK) return status;
    memset(out, 0, sizeof(*out));
    out->resource = (port - 1) / 4;
    out->lane = (port - 1) % 4;
    out->base = out->resource * 4 + 1;
    out->epl = epls[out->resource];
    out->mpo = out->resource / 3 + 1;
    out->shift = (out->resource % 3) * 4;
    count = NETLAB_XCVR_PROFILE_GET_ALL(entries, NL_MAX_PORTS_PER_PROFILE);
    if (count < 24 || count > NL_MAX_PORTS_PER_PROFILE) return FM_ERR_INVALID_ARGUMENT;
    for (int i = 0; i < count; ++i) {
        const nl_port_entry *p = &entries[i];
        if (!(p->flags & NL_PORT_FLAG_EXTERNAL)) continue;
        int n = p->logical_port - 1;
        if (n < 0 || n >= 24 || seen[n] || p->switch_id != sw ||
            p->port_index != n + 1 || p->epl_port != epls[n / 4] ||
            p->lane != n % 4 || p->hw_resource_id != (((n % 4) << 8) | (n / 4)) ||
            qsfp_lane_from_profile(p) != n % 4) return FM_ERR_INVALID_ARGUMENT;
        seen[n] = true;
    }
    for (int i = 0; i < 24; ++i) if (!seen[i]) return FM_ERR_INVALID_ARGUMENT;
    fm_platformCfgSwitch *cfg = NETLAB_XCVR_SWITCH_CFG(sw);
    if (!cfg || !cfg->ports || !NETLAB_XCVR_CACHE_INFO(sw)) return FM_ERR_UNINITIALIZED;
    for (int lane = 0; lane < 4; ++lane) {
        int logical = out->base + lane;
        fm_platformCfgPort *pcfg = NULL;
        fm_int physical = -1, platform = -1;
        fm_uint32 resource = 0;
        int index = NETLAB_XCVR_PORT_INDEX(sw, logical);
        if (NETLAB_XCVR_MAP_PORT(sw, logical, &physical, &platform, &resource, &pcfg) != FM_OK ||
            physical != sw || platform != sw || index != logical || index >= cfg->numPorts ||
            resource != (fm_uint32)((lane << 8) | out->resource) ||
            !pcfg || pcfg != &cfg->ports[index] || pcfg->portIdx != index ||
            pcfg->port != logical || pcfg->hwResourceId != resource || pcfg->epl != out->epl ||
            pcfg->autodetect ||
            pcfg->intfType != (fm_platIntfType)(FM_PLAT_INTF_TYPE_QSFP_LANE0 + lane) ||
            cfg->epls[out->epl].laneToPortIdx[lane] != index)
            return FM_ERR_INVALID_ARGUMENT;
        out->sdk_index[lane] = index;
    }
    out->fingerprint = fingerprint_u32(topology_fingerprint(entries, count), 0x46434931U);
    return FM_OK;
}
static fm_status fci_topology(fm_int sw, fm_int port, fci_port_topology *out) {
    fm_ethMode modes[4];
    fm_status status = fci_fixed_topology(sw, port, out);
    if (status != FM_OK) return status;
    for (int lane = 0; lane < 4; ++lane) {
        if (NETLAB_XCVR_ETHERNET_MODE(sw, out->base + lane, &modes[lane]) != FM_OK)
            return FM_FAIL;
        /* cfg.ports[].ethMode is the boot preference; the API and XCVR
         * runtime cache change independently during an online transition. */
        out->fingerprint = fingerprint_u32(out->fingerprint, (fm_uint32)modes[lane]);
    }
    out->aggregate = modes[0] == FM_ETH_MODE_100GBASE_SR4 || modes[0] == FM_ETH_MODE_40GBASE_SR4;
    for (int lane = 0; lane < 4; ++lane) {
        if (out->aggregate && lane) {
            if (modes[lane] != FM_ETH_MODE_DISABLED) return FM_ERR_UNSUPPORTED;
        } else if (!out->aggregate && modes[lane] != FM_ETH_MODE_10GBASE_SR &&
                   modes[lane] != FM_ETH_MODE_25GBASE_SR) return FM_ERR_UNSUPPORTED;
    }
    if (out->aggregate && out->lane) return FM_ERR_UNSUPPORTED;
    out->lane_mask = out->aggregate ? 15 : (fm_byte)(1U << out->lane);
    return FM_OK;
}
static fm_byte fci_disabled(const fci_port_topology *t, uint16_t tx) {
    return (fm_byte)(~(tx >> t->shift) & 15);
}
static fm_status fci_cache(fm_int sw, const fci_port_topology *t, uint16_t tx) {
    fm_platXcvrInfo *cache = NETLAB_XCVR_CACHE_INFO(sw);
    fm_byte disabled = fci_disabled(t, tx);
    if (!cache || (t->aggregate && disabled != 0 && disabled != 15))
        return FM_ERR_UNSUPPORTED;
    for (int lane = 0; lane < 4; ++lane)
        cache[t->sdk_index[lane]].disabled =
            (t->aggregate ? (lane != 0 || disabled != 0) : !!(disabled & (1U << lane))) ? TRUE : FALSE;
    return FM_OK;
}
static void fci_snapshot(const fci_port_topology *t, uint16_t tx,
                          netlab_port_xcvr_sdk_snapshot *out) {
    out->topology_fingerprint = t->fingerprint;
    out->module_hw_resource_id = (fm_uint32)t->resource;
    out->module_owner_port = t->base;
    out->lane_mask = t->lane_mask;
    out->present = TRUE;
    out->tx_disable_valid = TRUE;
    out->tx_disable_byte = fci_disabled(t, tx);
}
static fm_status fci_snapshot_get(fm_int sw, fm_int port,
                                  netlab_port_xcvr_sdk_snapshot *out) {
    fci_port_topology t;
    uint16_t tx;
    if (!out) return FM_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    fm_status status = fci_topology(sw, port, &t);
    if (status != FM_OK) return status;
    if (fci_bus.bus.enter(fci_bus.bus.context)) return FM_FAIL;
    /* Cache and I2C read belong to the same switch/bus critical section. */
    fm10k_bus reserved = fci_bus.bus;
    reserved.enter = reserved.leave = NULL;
    status = fm10k_tx_read(&reserved, t.mpo, &tx) ? FM_FAIL : fci_cache(sw, &t, tx);
    if (status == FM_OK) fci_snapshot(&t, tx, out);
    if (fci_bus.bus.leave(fci_bus.bus.context)) status = FM_FAIL;
    if (status != FM_OK) memset(out, 0, sizeof(*out));
    return status;
}
typedef struct { fm10k_bus *bus; fm_bool *attempted; } fci_write_ledger;
static int fci_ledger_read(void *context, uint8_t address, int reg, uint8_t *out, size_t n) {
    fci_write_ledger *ledger = context;
    return ledger->bus->read(ledger->bus->context, address, reg, out, n);
}
static int fci_ledger_write(void *context, uint8_t address, int reg, const uint8_t *in, size_t n) {
    fci_write_ledger *ledger = context;
    if (address == 0x50 && (reg == 56 || reg == 57)) *ledger->attempted = TRUE;
    return ledger->bus->write(ledger->bus->context, address, reg, in, n);
}
static fm_status fci_tx_disable_cas(fm_int sw, fm_int port,
                                    const netlab_port_xcvr_sdk_snapshot *expected,
                                    fm_byte desired, netlab_port_xcvr_sdk_cas_result *result) {
    fci_port_topology t;
    uint16_t tx, after;
    if (!result) return FM_ERR_INVALID_ARGUMENT;
    memset(result, 0, sizeof(*result));
    result->status = FM_ERR_INVALID_ARGUMENT;
    if (!expected || !expected->present || !expected->tx_disable_valid || desired > 15 ||
        expected->tx_disable_byte > 15 ||
        ((desired ^ expected->tx_disable_byte) & (fm_byte)~expected->lane_mask)) return result->status;
    fm_status status = fci_topology(sw, port, &t);
    if (status != FM_OK) goto done;
    if (expected->topology_fingerprint != t.fingerprint ||
        expected->module_hw_resource_id != (fm_uint32)t.resource ||
        expected->module_owner_port != t.base || expected->lane_mask != t.lane_mask) {
        status = FM_FAIL;
        goto done;
    }
    if (fci_bus.bus.enter(fci_bus.bus.context)) { status = FM_FAIL; goto done; }
    fci_write_ledger ledger = {.bus = &fci_bus.bus, .attempted = &result->write_attempted};
    fm10k_bus reserved = {.context = &ledger, .read = fci_ledger_read, .write = fci_ledger_write};
    if (fm10k_tx_read(&reserved, t.mpo, &tx) || fci_disabled(&t, tx) != expected->tx_disable_byte) {
        status = FM_FAIL;
        goto unlock;
    }
    uint16_t mask = (uint16_t)(t.lane_mask << t.shift);
    uint16_t enabled = (uint16_t)(((~desired) & t.lane_mask) << t.shift);
    status = fm10k_tx_update(&reserved, t.mpo, mask, enabled) ? FM_FAIL : FM_OK;
    /* Even a write that reports an error may have landed. Record observed
     * state for the existing admin transaction's compensation ledger. */
    if (!fm10k_tx_read(&reserved, t.mpo, &after)) {
        result->readback_completed = TRUE;
        result->readback_byte = fci_disabled(&t, after);
        if (fci_cache(sw, &t, after) != FM_OK || result->readback_byte != desired ||
            ((after ^ tx) & (uint16_t)~mask)) status = FM_FAIL;
    } else status = FM_FAIL;
unlock:
    if (fci_bus.bus.leave(fci_bus.bus.context)) status = FM_FAIL;
done:
    result->status = status;
    return status;
}

typedef struct {
    int sw;
    fm10k_group expected;
    const netlab_fm10k_group_control *control;
} fci_group_transaction;

int netlab_fm10k_group_sdk_get(int sw, int epl, fm10k_group *out) {
    int resource = fm10k_group_index(epl);
    if (!out || resource < 0 || !NETLAB_XCVR_FCI_PROFILE()) return FM10K_INVALID;
    memset(out, 0, sizeof(*out));
    fci_port_topology t;
    netlab_port_xcvr_sdk_snapshot optical;
    int base = resource * 4 + 1;
    if (fci_topology(sw, base, &t) != FM_OK ||
        fci_snapshot_get(sw, base, &optical) != FM_OK) return FM10K_IO;
    out->epl = epl;
    for (int lane = 0; lane < 4; ++lane) {
        fm_ethMode mode;
        fm_int admin, state, info[8] = {0};
        if (NETLAB_XCVR_ETHERNET_MODE(sw, base + lane, &mode) != FM_OK ||
            fmGetPortState(sw, base + lane, &admin, &state, info) != FM_OK)
            return FM10K_IO;
        if (!lane && t.aggregate) out->mode = mode == FM_ETH_MODE_100GBASE_SR4 ? 100 : 40;
        out->lane_gbps[lane] = t.aggregate ? (out->mode == 100 ? 25 : 10) :
            mode == FM_ETH_MODE_25GBASE_SR ? 25 : 10;
        if (admin != FM_PORT_MODE_UP && admin != FM_PORT_MODE_ADMIN_PWRDOWN)
            return FM10K_INVALID;
        if (t.aggregate && lane && admin != FM_PORT_MODE_ADMIN_PWRDOWN)
            return FM10K_INVALID;
        if (admin == FM_PORT_MODE_UP) out->enabled |= (uint8_t)(1U << lane);
    }
    uint8_t expected_disabled = (uint8_t)(~(t.aggregate ? (out->enabled ? 15 : 0) : out->enabled) & 15);
    return optical.tx_disable_byte == expected_disabled ? FM10K_OK : FM10K_IO;
}
static int fci_group_capture(void *context, int epl, fm10k_group *out) {
    fci_group_transaction *s = context;
    int rc = netlab_fm10k_group_sdk_get(s->sw, epl, out);
    return rc ? rc : fm10k_group_equal(out, &s->expected) ? FM10K_OK : FM10K_IO;
}
static int fci_group_quiesce(void *context, int epl, bool paused) {
    fci_group_transaction *s = context;
    return s->control->quiesce(s->control->context, epl, paused);
}
static void fci_group_degraded(void *context, int epl) {
    fci_group_transaction *s = context;
    s->control->degraded(s->control->context, epl);
}
static int fci_group_disable(void *context, int epl) {
    fci_group_transaction *s = context;
    fci_port_topology t;
    int index = fm10k_group_index(epl);
    if (index < 0 || fci_fixed_topology(s->sw, index * 4 + 1, &t) != FM_OK)
        return FM10K_INVALID;
    if (fci_bus.bus.enter(fci_bus.bus.context)) return FM10K_IO;
    fm10k_bus reserved = fci_bus.bus;
    reserved.enter = reserved.leave = NULL;
    uint16_t tx = 0;
    int rc = fm10k_tx_read(&reserved, t.mpo, &tx);
    if (!rc && ((tx >> t.shift) & 15)) rc = FM10K_IO;
    if (!rc) {
        fm_platXcvrInfo *info = NETLAB_XCVR_CACHE_INFO(s->sw);
        for (int lane = 0; lane < 4; ++lane) info[t.sdk_index[lane]].disabled = TRUE;
    }
    if (fci_bus.bus.leave(fci_bus.bus.context)) rc = FM10K_IO;
    if (rc) return rc;
    /* Complete all four attempts even after an error; never expand scope. */
    for (int lane = 0; lane < 4; ++lane) {
        fm_int admin, state, info[8] = {0};
        if (fmSetPortState(s->sw, t.base + lane, FM_PORT_MODE_ADMIN_PWRDOWN, 0) != FM_OK)
            rc = FM10K_IO;
        if (fmGetPortState(s->sw, t.base + lane, &admin, &state, info) != FM_OK ||
            admin != FM_PORT_MODE_ADMIN_PWRDOWN) rc = FM10K_IO;
    }
    return rc;
}

int netlab_fm10k_bootstrap_closed(int sw) {
    fci_port_topology topology;
    fci_group_transaction transaction = {.sw = sw};
    /* Prove every fixed resource before modifying either optical module. */
    for (int index = 0; index < 6; ++index)
        if (fci_fixed_topology(sw, index * 4 + 1, &topology) != FM_OK)
            return FM10K_INVALID;
    int rc = FM10K_OK;
    for (int mpo = 1; mpo <= 2; ++mpo)
        if (fm10k_tx_update(&fci_bus.bus, mpo, 0x0fff, 0)) rc = FM10K_IO;
    for (int index = 0; index < 6; ++index) {
        int epl = index < 3 ? index : index + 2;
        if (fci_group_disable(&transaction, epl)) rc = FM10K_IO;
    }
    for (int index = 0; index < 6; ++index) {
        fm10k_group actual;
        int epl = index < 3 ? index : index + 2;
        if (netlab_fm10k_group_sdk_get(sw, epl, &actual) || actual.enabled)
            rc = FM10K_IO;
    }
    return rc;
}
static int fci_mode_write(int sw, int port, fm_ethMode mode) {
    fm_ethMode actual;
    if (NETLAB_XCVR_ETHERNET_MODE(sw, port, &actual) != FM_OK) return FM10K_IO;
    if (actual == mode) return FM10K_OK;
    fm_status status = NETLAB_XCVR_SET_ETHERNET_MODE(sw, port, &mode);
    /* Read even after a reported write failure. Compensation re-reads each
     * lane and only acts inside the transaction's fixed four slots. */
    int rc = NETLAB_XCVR_ETHERNET_MODE(sw, port, &actual) != FM_OK || actual != mode;
    return status == FM_OK && !rc ? FM10K_OK : FM10K_IO;
}
static int fci_group_modes(void *context, const fm10k_group *g) {
    fci_group_transaction *s = context;
    int base = fm10k_group_index(g->epl) * 4 + 1;
    fm_ethMode target[4];
    bool same = true;
    for (int lane = 0; lane < 4; ++lane) {
        fm_int admin, state, info[8] = {0};
        fm_ethMode actual;
        target[lane] = g->mode ? (lane ? FM_ETH_MODE_DISABLED :
            g->mode == 100 ? FM_ETH_MODE_100GBASE_SR4 : FM_ETH_MODE_40GBASE_SR4) :
            g->lane_gbps[lane] == 25 ? FM_ETH_MODE_25GBASE_SR : FM_ETH_MODE_10GBASE_SR;
        if (fmGetPortState(s->sw, base + lane, &admin, &state, info) != FM_OK ||
            admin != FM_PORT_MODE_ADMIN_PWRDOWN ||
            NETLAB_XCVR_ETHERNET_MODE(s->sw, base + lane, &actual) != FM_OK)
            return FM10K_IO;
        if (actual != target[lane]) same = false;
    }
    if (same) return FM10K_OK;
    /* The pinned SDK validates the whole EPL arrangement on each write.
     * Remove the old aggregate/split shape before introducing a new one. */
    for (int lane = 0; lane < 4; ++lane)
        if (fci_mode_write(s->sw, base + lane, FM_ETH_MODE_DISABLED)) return FM10K_IO;
    for (int lane = 0; lane < 4; ++lane)
        if (fci_mode_write(s->sw, base + lane, target[lane])) return FM10K_IO;
    return FM10K_OK;
}
static int fci_group_restore(void *context, const fm10k_group *g) {
    fci_group_transaction *s = context;
    int base = fm10k_group_index(g->epl) * 4 + 1;
    netlab_port_xcvr_sdk_snapshot optical;
    /* Optical readback rebuilds live aggregate/split cache projections
     * before any admin-UP callback may consult the legacy SDK writer. */
    if (fci_snapshot_get(s->sw, base, &optical) != FM_OK) return FM10K_IO;
    uint8_t disabled = (uint8_t)(~(g->mode ? (g->enabled ? 15 : 0) : g->enabled) & 15);
    if (optical.tx_disable_byte != disabled) return FM10K_IO;
    for (int lane = 0; lane < 4; ++lane) {
        fm_int admin = g->enabled & (1U << lane) ? FM_PORT_MODE_UP : FM_PORT_MODE_ADMIN_PWRDOWN;
        if (fmSetPortState(s->sw, base + lane, admin, 0) != FM_OK) return FM10K_IO;
    }
    return FM10K_OK;
}
static int fci_group_verify(void *context, const fm10k_group *g) {
    fci_group_transaction *s = context;
    fm10k_group actual;
    int rc = netlab_fm10k_group_sdk_get(s->sw, g->epl, &actual);
    return rc ? rc : fm10k_group_equal(&actual, g) ? FM10K_OK : FM10K_IO;
}
int netlab_fm10k_group_sdk_apply(int sw, const fm10k_group *target,
                                 const fm10k_group *expected,
                                 const netlab_fm10k_group_control *control) {
    if (fm10k_group_validate(target) || fm10k_group_validate(expected) ||
        target->epl != expected->epl || !control || !control->quiesce || !control->degraded ||
        !NETLAB_XCVR_FCI_PROFILE() || fci_prepare(sw) != FM_OK) return FM10K_INVALID;
    fci_group_transaction transaction = {.sw = sw, .expected = *expected, .control = control};
    fm10k_group_ops ops = {&transaction, fci_group_capture, fci_group_quiesce,
        fci_group_disable, fci_group_modes, fci_group_restore, fci_group_verify, fci_group_degraded};
    return fm10k_group_apply(&fci_bus.bus, &ops, target);
}
