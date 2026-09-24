#include "../vendor/netlab/sbin/switchd/hal_vlan.c"
#include "../vendor/netlab/lib/libipc/stp_snapshot.c"
#include <assert.h>

static int scenario;
void nl_log_write(nl_log_level level, const char *file, int line, const char *format, ...) {
    (void)level; (void)file; (void)line; (void)format;
}
const char *fmErrorMsg(fm_int error) { (void)error; return "fixture"; }
bool nl_ifid_is_user_port(int port) {
    return port >= 1 && port <= (scenario == 8 ? 25 : 24);
}
fm_status fmGetVlanFirst(fm_int sw, fm_int *first) {
    assert(sw == 0);
    *first = scenario == 0 ? -1 : scenario == 4 ? 0 : 1;
    return scenario == 5 ? FM_FAIL : FM_OK;
}
fm_status fmGetVlanNext(fm_int sw, fm_int current, fm_int *next) {
    assert(sw == 0 && current == 1); *next = scenario == 6 ? 1 : -1; return FM_OK;
}
fm_status fmDeleteVlan(fm_int sw, fm_uint16 vlan) {
    assert(sw == 0 && vlan == 2); return FM_ERR_INVALID_VLAN;
}
fm_status fmGetVlanPortFirst(fm_int sw, fm_int vlan, fm_int *first) {
    assert(sw == 0 && vlan == 1);
    *first = scenario == 1 ? -1 : 0;
    return FM_OK;
}
fm_status fmGetVlanPortNext(fm_int sw, fm_int vlan, fm_int current, fm_int *next) {
    assert(sw == 0 && vlan == 1);
    *next = scenario == 3 ? -2 :
        (scenario == 7 || scenario == 8) ? (current < 25 ? current + 1 : -1) :
        current == 0 ? 1 : -1;
    return FM_OK;
}
fm_status fmGetVlanPortState(fm_int sw, fm_uint16 vlan, fm_int port, fm_int *state) {
    assert(sw == 0 && vlan == 1 && port >= 1 && port <= (scenario == 8 ? 25 : 24));
    *state = FM_STP_STATE_FORWARDING; return FM_OK;
}
int main(void) {
    struct sdk_result result = {0};
    for (scenario = 0; scenario <= 2; ++scenario) {
        assert(!hal_get_stp_table(0, &result));
        assert(result.data.stp_table.complete);
        assert(result.data.stp_table.n_entries == (scenario == 2 ? 1U : 0U));
        if (scenario == 2) {
            assert(result.data.stp_table.entries[0].port == 1);
            assert(result.data.stp_table.entries[0].state == FM_STP_STATE_FORWARDING);
        }
        nl_stp_snapshot_reset(&result.data.stp_table);
    }
    scenario = 3; assert(hal_get_stp_table(0, &result) != 0 && !result.data.stp_table.complete);
    scenario = 4; assert(hal_get_stp_table(0, &result) != 0 && !result.data.stp_table.complete);
    scenario = 7;
    assert(!hal_get_stp_table(0, &result));
    assert(result.data.stp_table.complete && result.data.stp_table.n_entries == 24U);
    assert(result.data.stp_table.entries[0].port == 1);
    assert(result.data.stp_table.entries[23].port == 24);
    nl_stp_snapshot_reset(&result.data.stp_table);
    scenario = 8;
    assert(hal_get_stp_table(0, &result) != 0 && !result.data.stp_table.complete);
    scenario = 0; assert(hal_vlan_presence_snapshot(0, 2).state == HAL_PRESENCE_ABSENT);
    assert(!hal_vlan_delete(0, 2)); /* Already absent after a new SDK baseline. */
    scenario = 1; assert(hal_vlan_presence_snapshot(0, 1).state == HAL_PRESENCE_PRESENT);
    for (scenario = 4; scenario <= 6; ++scenario) {
        assert(hal_vlan_presence_snapshot(0, 2).state == HAL_PRESENCE_READ_ERROR);
        assert(hal_vlan_delete(0, 2) != 0); /* Errors/cycles never prove absence. */
    }
    return 0;
}
