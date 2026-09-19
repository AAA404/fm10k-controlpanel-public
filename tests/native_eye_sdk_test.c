/* Exercise the real SDK adapter's admission and temporary Lane restoration. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fm_sdk_int.h>
#include <api/internal/fm10000/fm10000_api_ffu_int.h>
#include <api/internal/fm10000/fm10000_api_policer_int.h>
#include <fm_sdk_fm10000_int.h>

static fm10000_switch fake_switch;
static fm_rwLock fake_lock;
static fm_lock fake_state_lock;
static fm10000_lane fake_lane;
static fm10000_lane *fixture_lane(int);
static int write_locks, read_locks;
#define FM10K_EYE_SWITCH_EXT(sw) (&fake_switch)
#define FM10K_EYE_SWITCH_LOCK(sw) (&fake_lock)
#define FM10K_EYE_LANE_EXT(sw,sd) fixture_lane(sd)
#define FM10K_EYE_STATE_LOCK(sw) (&fake_state_lock)

static int time_sec=1;
static int fake_clock(clockid_t id, struct timespec *ts) {
    (void)id; ts->tv_sec=time_sec; ts->tv_nsec=0; return 0;
}
/* The pinned SDK's internal SerDes header has no include guard. Include the
 * production adapter first to preserve its required SDK header order. */
#define clock_gettime fake_clock
#include "../vendor/netlab/sbin/switchd/fm10k_eye.c"
#include "../hardware/native/fm10k_eye_scan.c"
#undef clock_gettime

static int link_state=FM_PORT_STATE_DOWN, mutations, pauses, resumes;
static int idle_pauses;
static bool serdes_zero_idle;
static fm10000SerdesLbMode lb=FM10000_SERDES_LB_OFF;
static fm10000SerdesTxDataSelect tx=FM10000_SERDES_TX_DATA_SEL_CORE;
static bool tx_failure, restore_failure;
static bool other_link_up, firmware_missing, other_dfe_busy;
static int fixture_port=13, fixture_serdes=20;
static bool first_group_split;
static unsigned master_version=FM10K_EYE_MASTER_VERSION, images_loaded, images_restored, upload_failure;
static bool master_reset_pending;
static bool signal_restore_failure;
static fm10000SerdesPolarity polarity=FM10000_SERDES_POLARITY_INVERT_RX;
static bool tx_output=true;
static unsigned signal_detect_cfg=0x1a;
static bool state_event_active;
static const int fixture_epls[]={0,1,2,5,6,7};
const fm_uint16 fm10000_sbus_master_code_prd[3338]={0}, fm10000_serdes_swap_code_prd2[7842]={0};
const fm_uint32 fm10000_sbus_master_code_size_prd=3338, fm10000_sbus_master_code_versionBuildId_prd=0x10130001;
const fm_uint32 fm10000_serdes_swap_code_size_prd2=7842, fm10000_serdes_swap_code_versionBuildId_prd2=0x20550045;
static nl_port_scope_status scope;
static unsigned cmp=0x8106, sampler_clock=0xc023;
static fm10000_lane *fixture_lane(int sd) {
    assert(sd==fixture_serdes);
    fake_lane.serDes=sd;
    fake_lane.smHandle=(fm_smHandle)&fake_lane;
    fake_lane.smType=FM10000_BASIC_SERDES_STATE_MACHINE;
    fake_lane.dfeMode=FM_DFE_MODE_STATIC;
    fake_lane.eventInfo.laneExt=&fake_lane;
    return &fake_lane;
}
fm_status fmGetStateMachineCurrentState(fm_smHandle handle,fm_int *state) {
    assert(handle==(fm_smHandle)&fake_lane);
    *state=lb==FM10000_SERDES_LB_INTERNAL_ON?FM10000_SERDES_STATE_LOOPBACK:FM10000_SERDES_STATE_POWERED_UP;
    return FM_OK;
}
fm_status fmNotifyStateMachineEvent(fm_smHandle handle,fm_smEventInfo *event,void *info,void *record) {
    assert(handle==(fm_smHandle)&fake_lane && info==&fake_lane.eventInfo && record==&fake_lane.serDes);
    assert(event->lock==&fake_state_lock && event->smType==FM10000_BASIC_SERDES_STATE_MACHINE);
    state_event_active=true;
    if(event->eventId==FM10000_SERDES_EVENT_LOOPBACK_ON_REQ) {
        fm10000SerdesSetPolarity(0,fixture_serdes,FM10000_SERDES_POLARITY_NONE);
        fm10000SerdesSetLoopbackMode(0,fixture_serdes,FM10000_SERDES_LB_INTERNAL_ON);
        fm10000SerdesTxRxEnaCtrl(0,fixture_serdes,FM10000_SERDES_CTRL_OUTPUT_ENA_MASK);
        fmWriteUINT32(0,FM10000_LANE_SIGNAL_DETECT_CFG(target.epl,target.lane),0x18);
    } else {
        assert(event->eventId==FM10000_SERDES_EVENT_LOOPBACK_OFF_REQ);
        fmWriteUINT32(0,FM10000_LANE_SIGNAL_DETECT_CFG(target.epl,target.lane),0x1a);
        fm10000SerdesSetLoopbackMode(0,fixture_serdes,FM10000_SERDES_LB_INTERNAL_OFF);
        fm10000SerdesSetPolarity(0,fixture_serdes,FM10000_SERDES_POLARITY_INVERT_RX);
        fm10000SerdesTxRxEnaCtrl(0,fixture_serdes,FM10000_SERDES_CTRL_OUTPUT_ENA_MASK|FM10000_SERDES_CTRL_OUTPUT_ENA);
    }
    state_event_active=false;
    return FM_OK;
}
bool fm10k_native_profile(void) { return true; }
bool fm10k_native_bound(void) { return true; }
bool nl_port_scope_ready(void) { return true; }
nl_port_scope_status nl_port_scope_get(void) { return scope; }
fm_status fmPlatformMgmtTakeSwitchLock(fm_int sw) { assert(!sw); ++read_locks; return FM_OK; }
fm_status fmPlatformMgmtDropSwitchLock(fm_int sw) { assert(!sw && read_locks>0); --read_locks; return FM_OK; }
fm_status fmCaptureWriteLock(fm_rwLock *lock,fm_timestamp *timeout) {
    assert(lock==&fake_lock && timeout==FM_WAIT_FOREVER && !write_locks && read_locks);
    ++write_locks; return FM_OK;
}
fm_status fmReleaseWriteLock(fm_rwLock *lock) {
    assert(lock==&fake_lock && write_locks==1 && !read_locks && !target.master_changed);
    --write_locks; return FM_OK;
}
fm_status fmGetPortAttribute(fm_int sw, fm_int port, fm_int attr, void *out) {
    assert(!sw && (port==fixture_port || port==(fixture_port-1)/4*4+1));
    if(attr==FM_PORT_ETHERNET_INTERFACE_MODE)
        *(fm_ethMode *)out=first_group_split && port<=4?FM_ETH_MODE_25GBASE_SR:FM_ETH_MODE_100GBASE_SR4;
    else { assert(attr==FM_PORT_SPEED); *(fm_int *)out=first_group_split && port<=4?25000:100000; }
    return FM_OK;
}
fm_status fmGetNumPortLanes(fm_int sw,fm_int port,fm_int mac,fm_int *out) {
    assert(!sw && port>=1 && port<=21 && (port%4==1 || (first_group_split && port<=4)) && !mac);
    *out=first_group_split && port<=4?1:4; return FM_OK;
}
fm_status fmGetPortState(fm_int sw,fm_int port,fm_int *admin,fm_int *state,fm_int *info) {
    (void)info; assert(!sw && port>=1 && port<=21 && (port%4==1 || (first_group_split && port<=4)));
    *admin=FM_PORT_MODE_UP;
    *state=port==fixture_port?link_state:port==1 && other_link_up?FM_PORT_STATE_UP:FM_PORT_STATE_DOWN; return FM_OK;
}
fm_status fm10000MapPortLaneToSerdes(fm_int sw,fm_int port,fm_int lane,fm_int *out) {
    assert(!sw && port>=1 && port<=21 && lane>=0 && lane<4);
    if(first_group_split && port<=4) { assert(!lane); *out=port-1; }
    else { assert(port%4==1); *out=fixture_epls[(port-1)/4]*4+lane; }
    return FM_OK;
}
fm_status fm10000MapSerdesToSbus(fm_int sw,fm_int serdes,fm_uint *addr,fm_serdesRing *ring) {
    assert(!sw && serdes==fixture_serdes); *addr=serdes+1; *ring=FM10000_SERDES_RING_EPL; return FM_OK;
}
fm_status fm10000SerDesGetBuildRevisionId(fm_int sw,fm_int serdes,fm_uint *out) {
    assert(!sw && serdes>=0 && serdes<32); *out=0x20550045; return FM_OK;
}
fm_status fm10000SbmGetBuildRevisionId(fm_int sw,fm_serdesRing ring,fm_uint *out) {
    assert(!sw && ring==FM10000_SERDES_RING_EPL); *out=master_version; return FM_OK;
}
fm_status fm10000SerdesDmaRead(fm_int sw,fm_int serdes,fm10000SerdesDmaType type,fm_uint reg,fm_uint32 *out) {
    assert(!sw && serdes==fixture_serdes);
    assert((type==FM10000_SERDES_DMA_TYPE_LSB &&
           (reg==0x0c || reg==0x17 || reg==0x1c || reg==0x21 || reg==0x24)) ||
           (type==FM10000_SERDES_DMA_TYPE_ESB && (reg==4 || reg==0x213)));
    *out=reg==0x17?cmp:reg==0x0c?sampler_clock:reg==0x213 && tx_output?2:0; return FM_OK;
}
fm_status fm10000SbmSpicoInt(fm_int sw,fm_serdesRing ring,fm_int addr,fm_uint irq,fm_uint32 data,fm_uint32 *out) {
    assert(!sw && ring==FM10000_SERDES_RING_EPL && addr==FM10000_SBUS_SPICO_BCAST_ADDR);
    if(irq==2 || irq==0x1a) { assert(!data); *out=0x00010001; return FM_OK; }
    assert(irq==0x2f);
    *out=data ? 0x002f0001 : 0x00000001; return FM_OK;
}
fm_status fm10000SbmSpicoIntWrite(fm_int sw,fm_serdesRing ring,fm_uint addr,fm_uint irq,fm_uint32 data) {
    (void)data; assert(!sw && ring==FM10000_SERDES_RING_EPL && addr==FM10000_SBUS_SPICO_BCAST_ADDR && irq==0x2f);
    return FM_OK;
}
fm_status fm10000SerdesSpicoInt(fm_int sw,fm_int serdes,fm_uint irq,fm_uint32 data,fm_uint32 *out) {
    assert(!sw && serdes>=0 && serdes<32); *out=irq&255;
    if(irq==0x126) { *out=other_dfe_busy && serdes==0?0x01:serdes_zero_idle && serdes==0?0x80:0x291; return FM_OK; }
    assert(serdes==fixture_serdes || irq==0x0a);
    ++mutations;
    if(irq==0x0a) {
        if(data==0) { ++pauses; if(serdes_zero_idle && serdes==0) ++idle_pauses; }
        else { assert(data==15 && !(serdes_zero_idle && serdes==0)); ++resumes; }
    }
    if(irq==3) cmp=(data&0x770)|1;
    if(irq==0x0f && data==0x100) sampler_clock&=~2U;
    return FM_OK;
}
fm_status fmReadUncachedUINT32(fm_int sw,fm_uint reg,fm_uint32 *out) {
    if(reg==(fm_uint)FM10000_LANE_SIGNAL_DETECT_CFG(target.epl,target.lane)) {
        assert(!sw); *out=signal_detect_cfg; return FM_OK;
    }
    bool allowed=false;
    for(unsigned g=0;g<6;++g) for(unsigned lane=0;lane<4;++lane) {
        if(reg==(fm_uint)FM10000_LANE_SAI_STATUS(fixture_epls[g],lane)) { *out=0x1000a; return FM_OK; }
        allowed|=reg==(fm_uint)FM10000_LANE_SERDES_STATUS(fixture_epls[g],lane);
    }
    assert(!sw && allowed); *out=0x07002000; return FM_OK;
}
fm_status fmWriteUINT32(fm_int sw,fm_uint reg,fm_uint32 value) {
    assert(!sw && reg==(fm_uint)FM10000_LANE_SIGNAL_DETECT_CFG(target.epl,target.lane));
    assert(value==0x18 || value==0x1a);
    if(!signal_restore_failure || value!=target.signal_detect_before) signal_detect_cfg=value;
    ++mutations; return FM_OK;
}
fm_status fm10000SerdesGetPolarity(fm_int sw,fm_int serdes,fm10000SerdesPolarity *out) {
    assert(!sw && serdes==fixture_serdes); *out=polarity; return FM_OK;
}
fm_status fm10000SerdesSetPolarity(fm_int sw,fm_int serdes,fm10000SerdesPolarity value) {
    assert(!sw && serdes==fixture_serdes);
    assert(value==FM10000_SERDES_POLARITY_NONE || value==FM10000_SERDES_POLARITY_INVERT_RX);
    polarity=value; ++mutations; return FM_OK;
}
fm_status fm10000SerdesTxRxEnaCtrl(fm_int sw,fm_int serdes,fm_uint32 control) {
    assert(!sw && serdes==fixture_serdes);
    assert((control&FM10000_SERDES_CTRL_OUTPUT_ENA_MASK) &&
           !(control&~(FM10000_SERDES_CTRL_OUTPUT_ENA_MASK|FM10000_SERDES_CTRL_OUTPUT_ENA)));
    tx_output=(control&FM10000_SERDES_CTRL_OUTPUT_ENA)!=0; ++mutations; return FM_OK;
}
void fm10000SerDesSaiSetDebug(fm_int sw,fm_int debug) {
    assert(!sw && (debug==0xfe || debug==0xff)); fake_switch.eplUseSbusIntf=debug==0xfe;
}
fm_status fm10000SerdesGetLoopbackMode(fm_int sw,fm_int serdes,fm10000SerdesLbMode *out) {
    assert(!sw && serdes==fixture_serdes); *out=lb; return FM_OK;
}
fm_status fm10000SerdesGetTxDataSelect(fm_int sw,fm_int serdes,fm10000SerdesTxDataSelect *out) {
    assert(!sw && serdes==fixture_serdes); *out=tx; return FM_OK;
}
fm_status fm10000SerdesGetTxRxReadyStatus(fm_int sw,fm_uint serdes,fm_bool *tx_ready,fm_bool *rx_ready) {
    assert(!sw && serdes==(fm_uint)fixture_serdes); *tx_ready=*rx_ready=TRUE; return FM_OK;
}
fm_status fm10000SerdesSetLoopbackMode(fm_int sw,fm_int serdes,fm10000SerdesLbMode mode) {
    assert(state_event_active);
    assert(!sw && serdes==fixture_serdes); ++mutations;
    assert(!target.temporary_master || master_version==0x10130001);
    assert(!target.temporary_master || !fake_switch.eplUseSbusIntf);
    assert(mode==FM10000_SERDES_LB_INTERNAL_ON || mode==FM10000_SERDES_LB_INTERNAL_OFF);
    if(mode==FM10000_SERDES_LB_INTERNAL_ON)
        assert(tx==FM10000_SERDES_TX_DATA_SEL_CORE && polarity==FM10000_SERDES_POLARITY_NONE);
    if(mode==FM10000_SERDES_LB_INTERNAL_OFF) {
        assert(restore_failure || tx==FM10000_SERDES_TX_DATA_SEL_CORE);
        assert(signal_restore_failure || (signal_detect_cfg&3U)==2);
        sampler_clock&=~2U;
    }
    lb=mode==FM10000_SERDES_LB_INTERNAL_ON?mode:FM10000_SERDES_LB_OFF;
    return FM_OK;
}
fm_status fm10000SerdesSetTxDataSelect(fm_int sw,fm_int serdes,fm10000SerdesTxDataSelect mode) {
    assert(!sw && serdes==fixture_serdes && mode==FM10000_SERDES_TX_DATA_SEL_PRBS31);
    assert(lb==FM10000_SERDES_LB_INTERNAL_ON && !tx_output && !(signal_detect_cfg&3U));
    assert(!target.temporary_master || master_version==0x10130001);
    assert(!target.temporary_master || !fake_switch.eplUseSbusIntf);
    ++mutations; tx=mode; return tx_failure?FM_FAIL:FM_OK;
}
fm_status fm10000SerdesDisablePrbsGen(fm_int sw,fm_int serdes,fm10000SerdesSelect select) {
    assert(!sw && serdes==fixture_serdes && select==FM10000_SERDES_SEL_TX);
    assert(!target.temporary_master || master_version==0x10130001);
    assert(!target.temporary_master || !fake_switch.eplUseSbusIntf);
    ++mutations;
    if(restore_failure) return FM_FAIL;
    tx=FM10000_SERDES_TX_DATA_SEL_CORE; return FM_OK;
}
fm_status fm10000SbusRead(fm_int sw,fm_bool epl,fm_uint addr,fm_uint reg,fm_uint32 *out) {
    (void)reg; assert(!sw && epl && (addr==FM10000_SBUS_SPICO_BCAST_ADDR || addr==FM10000_SBUS_CONTROLLER_ADDR || addr==(unsigned)fixture_serdes+1));
    *out=1; return FM_OK;
}
fm_status fm10000SbusWrite(fm_int sw,fm_bool epl,fm_uint addr,fm_uint reg,fm_uint32 data) {
    (void)data; assert(!sw && epl && addr==FM10000_SBUS_CONTROLLER_ADDR && (reg==0x11 || reg==0x12));
    return FM_OK;
}
int fm10k_eye_firmware_read(const char *path,uint16_t out[FM10K_EYE_MASTER_WORDS]) {
    assert(!strcmp(path,FM10K_EYE_MASTER_PATH)); memset(out,0,FM10K_EYE_MASTER_WORDS*2);
    return firmware_missing?-1:0;
}
fm_status fm10000SbusSbmReset(fm_int sw,fm_bool epl) {
    assert(!sw && epl && target.exclusive_lock && target.prepare_index==24);
    master_reset_pending=true; return FM_OK;
}
fm_status fm10000SbmSpicoUploadImage(fm_int sw,fm_serdesRing ring,fm_uint addr,const fm_uint16 *image,fm_int words) {
    assert(!sw && ring==FM10000_SERDES_RING_EPL && addr==FM10000_SBUS_SPICO_BCAST_ADDR);
    assert(master_reset_pending); master_reset_pending=false;
    if(words==FM10K_EYE_MASTER_WORDS) {
        assert(image==eye_master_image);
        assert(!target.internal_loopback || (lb==FM10000_SERDES_LB_INTERNAL_ON && tx==FM10000_SERDES_TX_DATA_SEL_PRBS31));
        ++images_loaded; master_version=FM10K_EYE_MASTER_VERSION;
    }
    else {
        assert(words==3338 && image==fm10000_sbus_master_code_prd); ++images_restored;
        if(upload_failure!=2) master_version=0x10130001;
    }
    return (upload_failure==1 && words==FM10K_EYE_MASTER_WORDS) || (upload_failure==2 && words==3338)?FM_FAIL:FM_OK;
}
fm_status fm10000SerdesSwapUploadImage(fm_int sw,fm_serdesRing ring,fm_uint addr,const fm_uint16 *image,fm_int words) {
    assert(!sw && ring==FM10000_SERDES_RING_EPL && addr==FM10000_SBUS_SPICO_BCAST_ADDR);
    assert(words==7842 && image==fm10000_serdes_swap_code_prd2); return FM_OK;
}
static char out[8192];
static char start_cmd[128]="start aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 13 0 16 4 100000 internal_loopback";
static void command(const char *cmd) { assert(!fm10k_eye_command(0,cmd,true,out,sizeof(out))); }
static void reset(void) { memset(&scan,0,sizeof(scan)); }
static void finish_preparation(void) {
    for(int n=0;n<100 && fm10k_eye_active(&scan) && !scan.preparation_done;++n) fm10k_eye_poll(0);
}
int main(void) {
    command("start aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 13 0 16 4 100000 external");
    assert(strstr(out,"no_signal") && !mutations);
    link_state=FM_PORT_STATE_UP; command(start_cmd);
    assert(strstr(out,"loopback_requires_link_down") && !mutations);
    link_state=FM_PORT_STATE_DOWN; lb=FM10000_SERDES_LB_INTERNAL_ON; command(start_cmd);
    assert(strstr(out,"loopback_already_configured") && !mutations);
    lb=FM10000_SERDES_LB_OFF; scope.mask=1; command(start_cmd);
    assert(strstr(out,"configuration_busy") && !mutations); scope.mask=0;
    command("start aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 13 0 16 4 100000 bad_source");
    assert(strstr(out,"invalid_parameters") && !mutations);
    command(start_cmd); assert(scan.state==EYE_PREPARING && pauses==1 && !lb && tx==0);
    fm10k_eye_poll(0); assert(lb==FM10000_SERDES_LB_INTERNAL_ON && tx==FM10000_SERDES_TX_DATA_SEL_PRBS31);
    command("cancel aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); fm10k_eye_poll(0);
    assert(scan.state==EYE_CANCELLED && scan.restored && !lb && tx==0 && pauses==resumes+idle_pauses);
    reset(); command(start_cmd); link_state=FM_PORT_STATE_UP; fm10k_eye_poll(0);
    assert(scan.state==EYE_FAILED && scan.restored && !lb && tx==0 && pauses==resumes+idle_pauses);
    reset(); link_state=FM_PORT_STATE_DOWN; tx_failure=true; command(start_cmd); fm10k_eye_poll(0);
    assert(scan.state==EYE_FAILED && scan.restored && !lb && tx==0 && pauses==resumes+idle_pauses);
    reset(); tx_failure=false; command(start_cmd); fm10k_eye_poll(0); restore_failure=true;
    command("cancel aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); fm10k_eye_poll(0);
    assert(scan.restore_failed && !scan.restored && !lb && pauses==resumes+idle_pauses);
    command("start bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 13 0 16 4 100000 internal_loopback");
    assert(strstr(out,"restore_failed"));
    reset(); restore_failure=false; tx=FM10000_SERDES_TX_DATA_SEL_CORE;
    master_version=0x10130001; other_link_up=true; int before=mutations; command(start_cmd);
    assert(strstr(out,"master_requires_offline_board") && mutations==before && !images_loaded);
    other_link_up=false; firmware_missing=true; command(start_cmd);
    assert(strstr(out,"master_firmware_unavailable") && mutations==before);
    firmware_missing=false; other_dfe_busy=true; command(start_cmd); fm10k_eye_poll(0); fm10k_eye_poll(0);
    assert(scan.state==EYE_PREPARING && !images_loaded && target.other_dfe_paused && fake_switch.eplUseSbusIntf);
    command("cancel aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); fm10k_eye_poll(0);
    assert(scan.restored && !images_loaded && pauses==resumes+idle_pauses && !fake_switch.eplUseSbusIntf && !write_locks);
    reset(); other_dfe_busy=false; command(start_cmd); finish_preparation();
    assert(images_loaded==1 && scan.target.temporary_master && master_version==FM10K_EYE_MASTER_VERSION && fake_switch.eplUseSbusIntf && write_locks==1);
    command("cancel aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); fm10k_eye_poll(0);
    assert(scan.restored && !scan.restore_failed && images_restored==1 && master_version==0x10130001 && !lb && tx==0 && !fake_switch.eplUseSbusIntf && !write_locks);
    reset(); upload_failure=1; command(start_cmd); finish_preparation();
    assert(scan.state==EYE_FAILED && scan.restored && images_restored==2 && master_version==0x10130001 && !lb && tx==0 && !write_locks);
    reset(); upload_failure=0; command(start_cmd); finish_preparation();
    assert(!fm10k_eye_shutdown(0) && scan.state==EYE_CANCELLED && scan.restored && !write_locks && !read_locks);
    /* EPL0 uses SerDes zero for P1; split ports pass SDK lane zero even when
     * their physical Lane is nonzero. Exercise both ends of the split group. */
    first_group_split=true;
    serdes_zero_idle=true;
    const int split_ports[]={1,1,4};
    for(unsigned n=0;n<sizeof(split_ports)/sizeof(split_ports[0]);++n) {
        int port=split_ports[n];
        reset(); fixture_port=port; fixture_serdes=port-1;
        snprintf(start_cmd,sizeof(start_cmd),"start aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa %d %d 16 4 100000 internal_loopback",port,port-1);
        command(start_cmd); finish_preparation();
        assert(scan.preparation_done && scan.target.port==port && scan.target.lane==port-1 &&
               scan.target.sbus==(unsigned)port && scan.target.speed_mbps==25000 && scan.target.temporary_master &&
               master_version==FM10K_EYE_MASTER_VERSION && write_locks==1);
        fm10k_eye_poll(0); /* Start a real sampling setup and mission column. */
        assert(scan.configured && scan.column_pending && cmp!=0x8106);
        command("cancel aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); fm10k_eye_poll(0);
        assert(scan.state==EYE_CANCELLED && scan.restored && !lb && tx==0 && pauses==resumes+idle_pauses &&
               (cmp&0x770)==0x100 && tx_output && polarity==FM10000_SERDES_POLARITY_INVERT_RX &&
               signal_detect_cfg==0x1a && master_version==0x10130001 &&
               !fake_switch.eplUseSbusIntf && !write_locks && !read_locks);
    }
    /* A successful write status with stale signal-control readback blocks reuse. */
    reset(); command(start_cmd); finish_preparation(); fm10k_eye_poll(0);
    signal_restore_failure=true;
    command("cancel aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); fm10k_eye_poll(0);
    assert(scan.state==EYE_FAILED && scan.restore_failed && !scan.restored && !lb && tx==0 &&
           master_version==0x10130001 && !write_locks && signal_detect_cfg==0x18);
    command("start bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 4 3 16 4 100000 internal_loopback");
    assert(strstr(out,"restore_failed"));
    /* Simulate the SDK recovery required after a failed restore. */
    signal_restore_failure=false; signal_detect_cfg=0x1a;
    reset(); upload_failure=0; command(start_cmd); finish_preparation(); upload_failure=2;
    command("cancel aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); fm10k_eye_poll(0);
    assert(scan.restore_failed && !scan.restored && scan.paused && lb==FM10000_SERDES_LB_INTERNAL_ON &&
           tx==FM10000_SERDES_TX_DATA_SEL_PRBS31 && master_version==FM10K_EYE_MASTER_VERSION &&
           pauses>resumes && fake_switch.eplUseSbusIntf && write_locks==1 && !read_locks);
    puts("eye SDK adapter: signal source guards, split P1/P4, master ordering and restoration passed");
}
