#include "fm10k_eye.h"
#include "fm10k_eye_scan.h"
#include "fm10k_eye_firmware.h"
#include "fm10k_board_runtime.h"
#include "netlab/port_scope.h"
#include <fm_sdk_int.h>
/* The shipped umbrella includes ACL before its FFU/policer dependencies. */
#include <api/internal/fm10000/fm10000_api_ffu_int.h>
#include <api/internal/fm10000/fm10000_api_policer_int.h>
#include <fm_sdk_fm10000_int.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Exported by the pinned IES 4.3.2 library; declarations match its source. */
extern fm_status fm10000SerdesSpicoInt(fm_int, fm_int, fm_uint, fm_uint32, fm_uint32 *);
extern fm_status fm10000SbmSpicoInt(fm_int, fm_serdesRing, fm_int, fm_uint, fm_uint32, fm_uint32 *);
extern fm_status fm10000SbmSpicoIntWrite(fm_int, fm_serdesRing, fm_uint, fm_uint, fm_uint32);
extern fm_status fm10000SerdesDmaRead(fm_int, fm_int, fm10000SerdesDmaType, fm_uint, fm_uint32 *);
extern const fm_uint16 fm10000_sbus_master_code_prd[], fm10000_serdes_swap_code_prd2[];
extern const fm_uint32 fm10000_sbus_master_code_size_prd, fm10000_sbus_master_code_versionBuildId_prd;
extern const fm_uint32 fm10000_serdes_swap_code_size_prd2, fm10000_serdes_swap_code_versionBuildId_prd2;

static fm10k_eye_scan scan;
#ifndef FM10K_EYE_SWITCH_EXT
#define FM10K_EYE_SWITCH_EXT(sw) GET_SWITCH_EXT(sw)
#endif
#ifndef FM10K_EYE_SWITCH_LOCK
#define FM10K_EYE_SWITCH_LOCK(sw) (fmRootApi->fmSwitchLockTable[(sw)])
#endif
#ifndef FM10K_EYE_LANE_EXT
#define FM10K_EYE_LANE_EXT(sw,sd) GET_LANE_EXT((sw),(sd))
#endif
#ifndef FM10K_EYE_STATE_LOCK
#define FM10K_EYE_STATE_LOCK(sw) FM_GET_STATE_LOCK(sw)
#endif
/* Verified against the pinned amd64 library's fm10000SerDesSaiSetDebug. */
_Static_assert(offsetof(fm10000_switch,eplUseSbusIntf)==0x3747a0,
               "Unexpected private SDK ABI for SerDes transport selection");
_Static_assert(offsetof(fm_switch,laneTable)==0x48 && offsetof(fm_switch,stateLock)==0x251b0 &&
               offsetof(fm_lane,extension)==0x58 && offsetof(fm10000_lane,smHandle)==0x20 &&
               offsetof(fm10000_lane,smType)==0x28 && offsetof(fm10000_lane,dfeMode)==0x40 &&
               offsetof(fm10000_lane,eventInfo)==0x180,
               "Unexpected private SDK ABI for the SerDes state machine");
static uint16_t eye_master_image[FM10K_EYE_MASTER_WORDS];
static struct {
    int sw, serdes, epl, lane, port;
    bool internal_loopback, prepared, temporary_master, master_changed;
    fm10000SerdesTxDataSelect tx_before;
    fm10000SerdesPolarity polarity_before;
    uint32_t signal_detect_before;
    bool tx_output_before;
    int quiet_serdes[24];
    uint32_t quiet_status[24];
    uint32_t other_dfe_paused;
    uint32_t other_dfe_resume;
    bool target_pause_issued, target_dfe_resume;
    uint32_t prepared_lanes;
    unsigned prepare_index;
    bool sbus_selected, sbus_before;
    fm_rwLock *exclusive_lock;
} target;
static pthread_t owner_thread;
static bool owner_set;
static atomic_bool poll_active;
unsigned fm10k_eye_poll_interval_us(void) {
    return atomic_load_explicit(&poll_active,memory_order_relaxed)?50000:250000;
}
static int check_owner(void) {
    if(!owner_set) { owner_thread=pthread_self(); owner_set=true; }
    return pthread_equal(owner_thread,pthread_self())?0:-1;
}
static int release_exclusive(void) {
    if(!target.exclusive_lock) return 0;
    if(fmReleaseWriteLock(target.exclusive_lock)!=FM_OK) {
        scan.restore_failed=true; scan.restored=false;
        return -1;
    }
    target.exclusive_lock=NULL;
    return 0;
}
static uint64_t eye_now(void *context) {
    (void)context;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
static int resume_dfe(int sd, bool was_running) {
    fm_uint32 value=0;
    if(was_running)
        return fm10000SerdesSpicoInt(target.sw,sd,0x0a,0x0f,&value)==FM_OK && (value&255)==0x0a?0:-1;
    /* The pinned 0x2055 firmware must not receive RESUME for an already-idle
     * DFE. Keep that state stopped and verify it without issuing 0x0a/0x0f. */
    return fm10000SerdesSpicoInt(target.sw,sd,0x126,0x0b00,&value)==FM_OK && !(value&0x77)?0:-1;
}
static int serdes(void *context, unsigned irq, unsigned data, uint32_t *reply) {
    (void)context;
    if(irq==0x0a && data==0) {
        fm_uint32 before=0;
        if(fm10000SerdesSpicoInt(target.sw,target.serdes,0x126,0x0b00,&before)!=FM_OK) return -1;
        target.target_dfe_resume=scan.target.firmware!=0x20550045 || (before&0x77)!=0;
        target.target_pause_issued=true;
        fprintf(stderr,"FM10840 eye: DFE P%d/L%d before=0x%x resume=%d\n",target.port,target.lane,before,target.target_dfe_resume);
    } else if(irq==0x0a && data==0x0f) {
        *reply=0x0a;
        return target.target_pause_issued?resume_dfe(target.serdes,target.target_dfe_resume):0;
    }
    return fm10000SerdesSpicoInt(target.sw, target.serdes, irq, data, reply) == FM_OK ? 0 : -1;
}
static int master(void *context, unsigned data, uint32_t *reply, bool wait) {
    (void)context;
    if (!wait) return fm10000SbmSpicoIntWrite(target.sw, FM10000_SERDES_RING_EPL,
        FM10000_SBUS_SPICO_BCAST_ADDR, 0x2f, data) == FM_OK ? 0 : -1;
    fm_uint32 raw = 0;
    int rc = fm10000SbmSpicoInt(target.sw, FM10000_SERDES_RING_EPL,
        FM10000_SBUS_SPICO_BCAST_ADDR, 0x2f, data, &raw);
    *reply = raw >> 16;
    return rc == FM_OK ? 0 : -1;
}
static int read_sbus(void *context, unsigned reg, uint32_t *out) {
    (void)context;
    if (reg != 0x08 && reg != 0x12 && reg != 0x13 && reg != 0x16) return -1;
    return fm10000SbusRead(target.sw, TRUE,
        reg == 8 ? FM10000_SBUS_SPICO_BCAST_ADDR : FM10000_SBUS_CONTROLLER_ADDR,
        reg, out) == FM_OK ? 0 : -1;
}
static int write_sbus(void *context, unsigned reg, uint32_t data) {
    (void)context;
    if ((reg != 0x11 && reg != 0x12) || (reg == 0x12 && data)) return -1;
    return fm10000SbusWrite(target.sw, TRUE, FM10000_SBUS_CONTROLLER_ADDR, reg, data) == FM_OK ? 0 : -1;
}
static int compare(void *context, uint32_t *out) {
    (void)context;
    return fm10000SerdesDmaRead(target.sw, target.serdes, FM10000_SERDES_DMA_TYPE_LSB,
        0x17, out) == FM_OK ? 0 : -1;
}
/* The old SBM has no eye command. Only an entirely idle board may use the
 * separately supplied diagnostic image in volatile EPL master RAM. Neither
 * the PCIe ring nor a SerDes instruction image is changed. */
static int offline_ports(void) {
    for(int g=0;g<6;++g) {
        int base=g*4+1;
        fm_int lanes=0;
        if(fmGetNumPortLanes(target.sw,base,0,&lanes)!=FM_OK || (lanes!=1 && lanes!=4)) {
            fprintf(stderr,"FM10840 eye: offline admission P%d lane count=%d\n",base,lanes); return -1;
        }
        for(int p=base;p<base+(lanes==4?1:4);++p) {
            fm_int admin=-1,state=-1,info[8]={0};
            if(fmGetPortState(target.sw,p,&admin,&state,info)!=FM_OK ||
                (admin==FM_PORT_MODE_UP && state!=FM_PORT_STATE_DOWN)) {
                fprintf(stderr,"FM10840 eye: offline admission P%d admin=%d state=%d\n",p,admin,state); return -1;
            }
        }
    }
    return 0;
}
static int offline_board(bool capture) {
    static const int epls[]={0,1,2,5,6,7};
    if(offline_ports()) return -1;
    for(int g=0;g<6;++g) {
        int base=g*4+1;
        fm_int lanes=0;
        if(fmGetNumPortLanes(target.sw,base,0,&lanes)!=FM_OK) return -1;
        for(int lane=0;lane<4;++lane) {
            int index=g*4+lane;
            fm_int sd=-1;
            fm_uint32 flags=0,version=0,status=0;
            if(fm10000MapPortLaneToSerdes(target.sw,lanes==4?base:base+lane,lanes==4?lane:0,&sd)!=FM_OK ||
                fm10000SerDesGetBuildRevisionId(target.sw,sd,&version)!=FM_OK || version!=0x20550045 ||
                fm10000SerdesSpicoInt(target.sw,sd,0x126,0x0b00,&flags)!=FM_OK ||
                (!(flags&0x200) && (flags&0x37)) ||
                fmReadUncachedUINT32(target.sw,FM10000_LANE_SERDES_STATUS(epls[g],lane),&status)!=FM_OK) {
                fprintf(stderr,"FM10840 eye: offline admission EPL%d/L%d serdes=%d firmware=0x%x DFE=0x%x\n",epls[g],lane,sd,version,flags); return -1;
            }
            if(capture) { target.quiet_serdes[index]=sd; target.quiet_status[index]=status; }
            /* RX idle/activity are live inputs, not saved configuration. */
            else if(target.quiet_serdes[index]!=sd || ((target.quiet_status[index]^status)&0x03000000)) {
                fprintf(stderr,"FM10840 eye: offline restore EPL%d/L%d status=0x%x before=0x%x\n",epls[g],lane,status,target.quiet_status[index]); return -1;
            }
        }
    }
    return 0;
}
static int pause_offline_lane(unsigned index) {
    static const int epls[]={0,1,2,5,6,7};
    int g=(int)index/4, lane=(int)index%4, base=g*4+1;
    fm_uint32 flags=0,reply=0;
    if(!(target.prepared_lanes&(1U<<index))) {
        fm_int lanes=0,sd=-1;
        fm_uint32 version=0,status=0;
        if(fmGetNumPortLanes(target.sw,base,0,&lanes)!=FM_OK || (lanes!=1 && lanes!=4) ||
            fm10000MapPortLaneToSerdes(target.sw,lanes==4?base:base+lane,lanes==4?lane:0,&sd)!=FM_OK) return -2;
        if(fm10000SerDesGetBuildRevisionId(target.sw,sd,&version)!=FM_OK || !version) return 1;
        if(version!=0x20550045 ||
            fmReadUncachedUINT32(target.sw,FM10000_LANE_SERDES_STATUS(epls[g],lane),&status)!=FM_OK) return -2;
        if(sd!=target.serdes && fm10000SerdesSpicoInt(target.sw,sd,0x126,0x0b00,&flags)!=FM_OK) return -2;
        target.quiet_serdes[index]=sd;
        target.quiet_status[index]=status;
        target.prepared_lanes|=1U<<index;
        if(sd!=target.serdes) {
            if(flags&0x77) target.other_dfe_resume|=1U<<index;
            target.other_dfe_paused|=1U<<index;
            if(fm10000SerdesSpicoInt(target.sw,sd,0x0a,0,&reply)!=FM_OK || (reply&255)!=0x0a) return -2;
        }
    }
    if(fm10000SerdesSpicoInt(target.sw,target.quiet_serdes[index],0x126,0x0b00,&flags)!=FM_OK) return -2;
    /* Pause first, then wait for the current calibration to finish. LOS is
     * a suspended calibration, per the firmware's DFE wait contract. */
    return !(flags&0x200) && (flags&0x37) ? 1 : 0;
}
static int master_image(const fm_uint16 *image, unsigned words, unsigned version) {
    fm_uint32 actual=0,crc=0;
    /* Match the SDK's fm10000SmbSpicoSetup recovery sequence. Uploading
     * instruction RAM alone does not reset the master's SBus interface. */
    if(fm10000SbusSbmReset(target.sw,TRUE)!=FM_OK) return -1;
    usleep(FM10000_SERDES_RESET_DELAY);
    if(fm10000SbmSpicoUploadImage(target.sw,FM10000_SERDES_RING_EPL,
            FM10000_SBUS_SPICO_BCAST_ADDR,image,(fm_int)words)!=FM_OK ||
        fm10000SbmSpicoInt(target.sw,FM10000_SERDES_RING_EPL,FM10000_SBUS_SPICO_BCAST_ADDR,2,0,&crc)!=FM_OK ||
        (crc>>16)!=1 || fm10000SbmGetBuildRevisionId(target.sw,FM10000_SERDES_RING_EPL,&actual)!=FM_OK || actual!=version ||
        fm10000SerdesSwapUploadImage(target.sw,FM10000_SERDES_RING_EPL,FM10000_SBUS_SPICO_BCAST_ADDR,
            fm10000_serdes_swap_code_prd2,(fm_int)fm10000_serdes_swap_code_size_prd2)!=FM_OK ||
        fm10000SbmSpicoInt(target.sw,FM10000_SERDES_RING_EPL,FM10000_SBUS_SPICO_BCAST_ADDR,0x1a,0,&crc)!=FM_OK ||
        (crc>>16)!=1) {
        fprintf(stderr,"FM10840 eye: master RAM validation failed expected=0x%x actual=0x%x crc=0x%x\n",version,actual,crc);
        return -1;
    }
    fprintf(stderr,"FM10840 eye: master reset and validated version=0x%x\n",actual);
    return 0;
}
static int signal_present(void *context) {
    (void)context;
    fm_uint32 value;
    if (fmReadUncachedUINT32(target.sw, FM10000_LANE_SERDES_STATUS(target.epl, target.lane), &value) != FM_OK)
        return -1;
    if (target.internal_loopback) {
        fm10000SerdesLbMode loopback;
        fm10000SerdesTxDataSelect tx;
        if (fm10000SerdesGetLoopbackMode(target.sw,target.serdes,&loopback)!=FM_OK ||
            fm10000SerdesGetTxDataSelect(target.sw,target.serdes,&tx)!=FM_OK) return -1;
        return (value & (1U<<24)) && (value & (1U<<25)) &&
            loopback==FM10000_SERDES_LB_INTERNAL_ON && tx==FM10000_SERDES_TX_DATA_SEL_PRBS31 ? 0 : -1;
    }
    return (value & (1U << 24)) && !(value & (1U << 26)) ? 0 : -1;
}
static int select_sbus(bool enabled) {
    fm10000_switch *ext=FM10K_EYE_SWITCH_EXT(target.sw);
    if(!ext) return -1;
    fm10000SerDesSaiSetDebug(target.sw,enabled?0xfe:0xff);
    return (ext->eplUseSbusIntf!=0)==enabled?0:-1;
}
static int signal_detect(unsigned mode) {
    fm_uint reg=FM10000_LANE_SIGNAL_DETECT_CFG(target.epl,target.lane);
    fm_uint32 value=(target.signal_detect_before&~3U)|mode,actual=0;
    return fmWriteUINT32(target.sw,reg,value)==FM_OK &&
        fmReadUncachedUINT32(target.sw,reg,&actual)==FM_OK && actual==value?0:-1;
}
static int output_enable(bool enabled) {
    return fm10000SerdesTxRxEnaCtrl(target.sw,target.serdes,
        FM10000_SERDES_CTRL_OUTPUT_ENA_MASK | (enabled?FM10000_SERDES_CTRL_OUTPUT_ENA:0))==FM_OK?0:-1;
}
static int sdk_loopback(bool enabled) {
    fm10000_lane *lane=FM10K_EYE_LANE_EXT(target.sw,target.serdes);
    fm_int before=-1,after=-1;
    if(!lane || lane->serDes!=target.serdes || !lane->smHandle ||
        lane->smType!=FM10000_BASIC_SERDES_STATE_MACHINE) return -1;
    fm_smEventInfo event={.smType=lane->smType,.srcSmType=lane->smType,
        .eventId=enabled?FM10000_SERDES_EVENT_LOOPBACK_ON_REQ:FM10000_SERDES_EVENT_LOOPBACK_OFF_REQ,
        .lock=FM10K_EYE_STATE_LOCK(target.sw),.dontSaveRecord=FALSE};
    lane->eventInfo.info.dfeMode=lane->dfeMode;
    if(fmGetStateMachineCurrentState(lane->smHandle,&before)!=FM_OK) return -1;
    fm_status rc=fmNotifyStateMachineEvent(lane->smHandle,&event,&lane->eventInfo,&lane->serDes);
    if(fmGetStateMachineCurrentState(lane->smHandle,&after)!=FM_OK) return -1;
    fprintf(stderr,"FM10840 eye: SDK loopback P%d/L%d enabled=%d state=%d->%d status=%d\n",
            target.port,target.lane,enabled,before,after,rc);
    return rc==FM_OK?0:-1;
}
static void trace_source_failure(void) {
    fm_uint addr;
    fm_serdesRing ring;
    if(fm10000MapSerdesToSbus(target.sw,target.serdes,&addr,&ring)!=FM_OK) return;
    const unsigned regs[]={0x03,0x04,0x07,0x20,0x25};
    fm_uint32 values[5]={0};
    for(unsigned i=0;i<5;++i)
        if(fm10000SbusRead(target.sw,TRUE,addr,regs[i],&values[i])!=FM_OK) return;
    fprintf(stderr,"FM10840 eye: source failure P%d/L%d SPICO[03,04,07,20,25]=%x,%x,%x,%x,%x\n",
            target.port,target.lane,values[0],values[1],values[2],values[3],values[4]);
}
static int prepare_loopback(void *context) {
    (void)context;
    if(target.temporary_master) {
        if(offline_ports()) return -2;
        if(!target.sbus_selected) {
          fm10000_switch *ext=FM10K_EYE_SWITCH_EXT(target.sw);
          if(!ext) return -2;
          target.sbus_before=ext->eplUseSbusIntf!=0;
          target.sbus_selected=true;
        /* The reference SBM lacks Intel's SAI grant arbitration. Route both
         * our operations and the SDK TimerTask through its supported SBus
         * transport until the original master has been restored. */
          fm10000SerDesSaiSetDebug(target.sw,0xfe);
          if(!ext->eplUseSbusIntf) return -2;
          static const int epls[]={0,1,2,5,6,7};
          for(int g=0;g<6;++g) for(int lane=0;lane<4;++lane) {
            fm_uint32 status;
            if(fmReadUncachedUINT32(target.sw,FM10000_LANE_SAI_STATUS(epls[g],lane),&status)!=FM_OK ||
                (status&((1U<<19)|(1U<<18)))) return -2;
          }
          return 1;
        }
        if(target.prepare_index<24) {
            int rc=pause_offline_lane(target.prepare_index);
            if(rc<0) return rc;
            if(!rc) ++target.prepare_index;
            return 1;
        }
        if(offline_board(false)) return -2;
    }
    if(target.internal_loopback && !target.prepared) {
        /* The vendor master arbitrates normal source transitions over SAI.
         * The temporary reference master needs SBus only while sampling. */
        if(target.temporary_master && select_sbus(false)) return -2;
        /* The native owner holds the switch lock and has paused the target DFE.
         * Recheck Link Down immediately before changing the temporary source. */
        fm_int admin,state,info[8]={0};
        fm_uint32 flags=0;
        fm10000SerdesLbMode loopback;
        fm10000SerdesTxDataSelect tx;
        if (fmGetPortState(target.sw,target.port,&admin,&state,info)!=FM_OK || state!=FM_PORT_STATE_DOWN ||
            fm10000SerdesGetLoopbackMode(target.sw,target.serdes,&loopback)!=FM_OK ||
            fm10000SerdesGetTxDataSelect(target.sw,target.serdes,&tx)!=FM_OK ||
            loopback!=FM10000_SERDES_LB_OFF || tx!=target.tx_before ||
            fm10000SerdesSpicoInt(target.sw,target.serdes,0x126,0x0b00,&flags)!=FM_OK) return -1;
        target.prepared=true;
        /* Use the SDK's single-Lane state transition, including DFE stop and
         * cached state updates. Raw IRQ 0x08 alone bypasses that coordination. */
        fprintf(stderr,"FM10840 eye: preparing internal source P%d/L%d DFE=0x%x polarity=%d output=%d signal=0x%x\n",
                target.port,target.lane,flags,target.polarity_before,target.tx_output_before,target.signal_detect_before);
        if (sdk_loopback(true) ||
            fm10000SerdesSetTxDataSelect(target.sw,target.serdes,FM10000_SERDES_TX_DATA_SEL_PRBS31)!=FM_OK) {
            trace_source_failure();
            return -1;
        }
        if(signal_present(NULL)) return -1;
        if(target.temporary_master && select_sbus(true)) return -2;
        return 1; /* Allow RX/DFE to settle before changing the master image. */
    }
    if(target.temporary_master && !target.master_changed) {
        target.master_changed=true; /* Restore even if an upload error follows a write. */
        if(master_image(eye_master_image,FM10K_EYE_MASTER_WORDS,FM10K_EYE_MASTER_VERSION)) return -2;
    }
    return target.internal_loopback ? signal_present(NULL) : 0;
}
static int restore_loopback(void *context) {
    (void)context;
    int failed=0;
    fm10000SerdesLbMode loopback;
    fm10000SerdesTxDataSelect tx;
    /* Restore the vendor master before any RX-source transition. The eye
     * master is only used for sampling, not vendor loopback configuration. */
    if(target.master_changed) {
        for(int attempt=0;attempt<2 && target.master_changed;++attempt)
            if(!master_image(fm10000_sbus_master_code_prd,fm10000_sbus_master_code_size_prd,
                             fm10000_sbus_master_code_versionBuildId_prd)) target.master_changed=false;
        if(target.master_changed) return -2;
    }
    if(target.temporary_master && target.sbus_selected && select_sbus(false)) return -2;
    /* CORE was required at admission. Disable PRBS with 0x01ff only;
     * SetDataCoreSource also overwrites unrelated data-path register bits. */
    if(target.prepared) {
        fm10000SerdesPolarity polarity;
        fm_uint32 output=0;
        if (fm10000SerdesDisablePrbsGen(target.sw,target.serdes,FM10000_SERDES_SEL_TX)!=FM_OK) failed=1;
        if(sdk_loopback(false)) failed=1;
        if(fm10000SerdesSetPolarity(target.sw,target.serdes,target.polarity_before)!=FM_OK) failed=1;
        if(output_enable(target.tx_output_before)) failed=1;
        if(signal_detect(target.signal_detect_before&3U)) failed=1;
        if (fm10000SerdesGetTxDataSelect(target.sw,target.serdes,&tx)!=FM_OK || tx!=target.tx_before) failed=1;
        if (fm10000SerdesGetLoopbackMode(target.sw,target.serdes,&loopback)!=FM_OK || loopback!=FM10000_SERDES_LB_OFF) failed=1;
        if(fm10000SerdesGetPolarity(target.sw,target.serdes,&polarity)!=FM_OK || polarity!=target.polarity_before) failed=1;
        if(fm10000SerdesDmaRead(target.sw,target.serdes,FM10000_SERDES_DMA_TYPE_ESB,0x213,&output)!=FM_OK ||
            ((output&2U)!=0)!=target.tx_output_before) failed=1;
    }
    if(target.temporary_master && target.prepare_index==24 && offline_board(false)) failed=1;
    for(int i=0;i<24;++i) if(target.other_dfe_paused&(1U<<i)) {
        if(resume_dfe(target.quiet_serdes[i],(target.other_dfe_resume&(1U<<i))!=0)) failed=1;
    }
    target.other_dfe_paused=0;
    target.other_dfe_resume=0;
    if(target.sbus_selected) {
        fm10000_switch *ext=FM10K_EYE_SWITCH_EXT(target.sw);
        fm10000SerDesSaiSetDebug(target.sw,target.sbus_before?0xfe:0xff);
        if(!ext || (ext->eplUseSbusIntf!=0)!=target.sbus_before) failed=1;
        target.sbus_selected=false;
    }
    target.prepared=false;
    return failed ? -1 : 0;
}
static int problem(char *out, size_t capacity, const char *reason) {
    int n = snprintf(out, capacity, "{\"error\":\"%s\"}", reason);
    return n < 0 || (size_t)n >= capacity ? -1 : 0;
}
static const char *qualify(int sw, int port, int lane, bool internal, fm10k_eye_target *info) {
    static const int epls[] = {0,1,2,5,6,7};
    if (sw || port < 1 || port > 24 || lane < 0 || lane > 3) return "invalid_target";
    int base = (port-1)/4*4+1;
    fm_ethMode mode;
    fm_int lanes, admin, state, state_info[8] = {0}, speed;
    if (fmGetPortAttribute(sw, base, FM_PORT_ETHERNET_INTERFACE_MODE, &mode) != FM_OK)
        return "port_mode_unavailable";
    bool aggregate = mode == FM_ETH_MODE_100GBASE_SR4 || mode == FM_ETH_MODE_40GBASE_SR4;
    if (aggregate ? port != base : port != base + lane) return "port_lane_mismatch";
    if (fmGetNumPortLanes(sw, port, 0, &lanes) != FM_OK || lanes != (aggregate ? 4 : 1) ||
        fmGetPortState(sw, port, &admin, &state, state_info) != FM_OK || admin != FM_PORT_MODE_UP ||
        fmGetPortAttribute(sw, port, FM_PORT_SPEED, &speed) != FM_OK) return "port_disabled";
    if (aggregate) speed /= 4;
    if (speed != 10000 && speed != 25000) return "unsupported_speed";
    target.sw = sw; target.port = port; target.lane = lane; target.epl = epls[(port-1)/4];
    target.internal_loopback=internal; target.prepared=false; target.master_changed=false; target.temporary_master=false;
    target.other_dfe_paused=0;
    target.other_dfe_resume=0;
    target.target_pause_issued=false;
    target.target_dfe_resume=false;
    target.sbus_selected=false;
    target.prepare_index=0; target.prepared_lanes=0;
    fm_serdesRing ring;
    fm_uint addr;
    if (fm10000MapPortLaneToSerdes(sw, port, aggregate ? lane : 0, &target.serdes) != FM_OK ||
        fm10000MapSerdesToSbus(sw, target.serdes, &addr, &ring) != FM_OK ||
        ring != FM10000_SERDES_RING_EPL) return "serdes_mapping_failed";
    memset(info, 0, sizeof(*info));
    info->sbus = addr; info->port = port; info->lane = lane; info->epl = target.epl; info->speed_mbps = speed;
    info->internal_loopback=internal;
    fm_uint32 phase, cmp;
    if (fm10000SerDesGetBuildRevisionId(sw, target.serdes, &info->firmware) != FM_OK ||
        fm10000SbmGetBuildRevisionId(sw, ring, &info->master_firmware) != FM_OK ||
        compare(NULL, &cmp) ||
        fm10000SerdesDmaRead(sw, target.serdes, FM10000_SERDES_DMA_TYPE_ESB, 4, &phase) != FM_OK ||
        master(NULL, 0, &info->protocol, true)) return "firmware_probe_failed";
    info->phase_multiplier = 1U << (phase & 7); info->compare_mode = cmp & 0x770;
    if ((info->firmware >> 16) < 0x1049 || info->protocol == 0xffff ||
        info->phase_multiplier > 8) return "unsupported_firmware";
    fm10000SerdesLbMode loopback;
    if (fm10000SerdesGetLoopbackMode(sw,target.serdes,&loopback)!=FM_OK ||
        fm10000SerdesGetTxDataSelect(sw,target.serdes,&target.tx_before)!=FM_OK) return "loopback_probe_failed";
    if (internal) {
        if(info->firmware!=0x20550045) return "unsupported_firmware";
        if (state!=FM_PORT_STATE_DOWN) return "loopback_requires_link_down";
        /* Keep restoration exact; do not overwrite a pre-existing diagnostic
         * pattern, user pattern or parallel loopback. */
        if (loopback!=FM10000_SERDES_LB_OFF || target.tx_before!=FM10000_SERDES_TX_DATA_SEL_CORE)
            return "loopback_already_configured";
        fm_bool tx_ready,rx_ready;
        if (fm10000SerdesGetTxRxReadyStatus(sw,target.serdes,&tx_ready,&rx_ready)!=FM_OK ||
            !tx_ready || !rx_ready) return "serdes_not_ready";
        fm_uint32 output=0;
        if(fm10000SerdesGetPolarity(sw,target.serdes,&target.polarity_before)!=FM_OK ||
            fm10000SerdesDmaRead(sw,target.serdes,FM10000_SERDES_DMA_TYPE_ESB,0x213,&output)!=FM_OK ||
            fmReadUncachedUINT32(sw,FM10000_LANE_SIGNAL_DETECT_CFG(target.epl,target.lane),&target.signal_detect_before)!=FM_OK)
            return "loopback_probe_failed";
        target.tx_output_before=(output&2U)!=0;
    } else {
        if (loopback!=FM10000_SERDES_LB_OFF) return "loopback_already_configured";
        if (signal_present(NULL)) return "no_signal";
    }
    if(info->master_firmware==0x10130001) {
        if(info->firmware!=0x20550045 || fm10000_sbus_master_code_size_prd!=3338 ||
           fm10000_sbus_master_code_versionBuildId_prd!=0x10130001 ||
           fm10000_serdes_swap_code_size_prd2!=7842 ||
           fm10000_serdes_swap_code_versionBuildId_prd2!=0x20550045) return "unsupported_firmware";
        if(offline_ports()) return "master_requires_offline_board";
        if(fm10k_eye_firmware_read(FM10K_EYE_MASTER_PATH,eye_master_image)) return "master_firmware_unavailable";
        info->temporary_master=target.temporary_master=true;
    }
    return NULL;
}
int fm10k_eye_command(int sw, const char *command, bool control, char *out, size_t capacity) {
    if (!command || !out || !capacity || sw || !fm10k_native_profile() || check_owner()) return -1;
    char id[33] = {0}; unsigned column = 0; int used = 0;
    if (!control) {
        if (sscanf(command, "latest %u%n", &column, &used) == 1 && command[used] == 0) {
            if (column > scan.columns_done) return problem(out,capacity,"invalid_column");
            return fm10k_eye_format(&scan, column, out, capacity);
        }
        used = 0;
        if (sscanf(command,"get %32[0-9a-f] %u%n",id,&column,&used) == 2 && strlen(id)==32 && command[used]==0) {
            if (strcmp(id,scan.id)) return problem(out,capacity,"job_expired");
            if (column > scan.columns_done) return problem(out,capacity,"invalid_column");
            return fm10k_eye_format(&scan, column, out, capacity);
        }
        return problem(out,capacity,"invalid_command");
    }
    if (sscanf(command,"cancel %32[0-9a-f]%n",id,&used)==1 && strlen(id)==32 && command[used]==0) {
        if (strcmp(id,scan.id)) return problem(out,capacity,"job_expired");
        fm10k_eye_cancel(&scan,"user_cancelled");
        return fm10k_eye_format(&scan,0,out,capacity);
    }
    int port,lane; unsigned resolution,step,dwell; char source[24]="external";
    used=0;
    int fields=sscanf(command,"start %32[0-9a-f] %d %d %u %u %u%n",id,&port,&lane,&resolution,&step,&dwell,&used);
    if (fields==6 && command[used]) {
        int end=0;
        if (command[used]!=' ' || sscanf(command+used," %23[a-z_]%n",source,&end)!=1 || command[used+end])
            return problem(out,capacity,"invalid_parameters");
        used+=end;
    }
    bool internal=!strcmp(source,"internal_loopback");
    if (fields!=6 ||
        strlen(id)!=32 || command[used]!=0 ||
        (strcmp(source,"external") && !internal) ||
        (resolution!=16 && resolution!=32 && resolution!=64) ||
        (step!=1 && step!=2 && step!=4 && step!=8) || dwell<100000 || dwell>10000000 || dwell%20)
        return problem(out,capacity,"invalid_parameters");
    if (!strcmp(id,scan.id)) {
        if (port!=scan.target.port || lane!=scan.target.lane || resolution!=scan.x_resolution ||
            step!=scan.y_step || dwell!=scan.dwell_bits ||
            internal!=scan.target.internal_loopback) return problem(out,capacity,"id_conflict");
        return fm10k_eye_format(&scan,0,out,capacity);
    }
    if (fm10k_eye_active(&scan)) return problem(out,capacity,"eye_busy");
    if (scan.restore_failed) return problem(out,capacity,"restore_failed");
    nl_port_scope_status scope = nl_port_scope_get();
    if (!fm10k_native_bound() || !nl_port_scope_ready() || scope.tx_id || scope.mask || scope.degraded)
        return problem(out,capacity,"configuration_busy");
    if (fmPlatformMgmtTakeSwitchLock(sw)!=FM_OK) return problem(out,capacity,"sdk_lock_failed");
    fm10k_eye_target info = {0};
    const char *error = qualify(sw,port,lane,internal,&info);
    if(!error && info.temporary_master) {
        /* MgmtTakeSwitchLock is a shared READ lock; it does not exclude the
         * SDK TimerTask. The pinned SDK explicitly supports read calls made
         * by a write-lock owner. Retain its lowest-precedence WRITE lock on
         * this one executor thread until RAM/DFE restoration is complete.
         * Queued timer events then resume normally without changing any
         * Lane's DFE mode, equalizer settings or state-machine state. */
        fm_rwLock *lock=FM10K_EYE_SWITCH_LOCK(sw);
        if(!lock || fmCaptureWriteLock(lock,FM_WAIT_FOREVER)!=FM_OK) error="sdk_lock_failed";
        else target.exclusive_lock=lock;
    }
    if (!error) {
        fm10k_eye_io io = {.serdes=serdes,.master=master,.read=read_sbus,.write=write_sbus,
            .compare=compare,.signal=signal_present,.prepare=prepare_loopback,.restore=restore_loopback,.now=eye_now};
        struct timespec wall;
        if (clock_gettime(CLOCK_REALTIME,&wall) || fm10k_eye_start(&scan,&io,&info,id,resolution,step,dwell,
            wall.tv_sec+wall.tv_nsec/1e9)) error="unsupported_firmware";
    }
    if (fmPlatformMgmtDropSwitchLock(sw)!=FM_OK) {
        scan.restore_failed=true;
        error="sdk_unlock_failed";
    }
    if((error || !fm10k_eye_active(&scan)) && !target.master_changed && release_exclusive())
        error="sdk_unlock_failed";
    atomic_store_explicit(&poll_active,fm10k_eye_active(&scan),memory_order_relaxed);
    if (error) {
        int n=snprintf(out,capacity,"{\"error\":\"%s\",\"firmware\":%u,\"master_firmware\":%u,\"protocol\":%u,\"phase_multiplier\":%u,\"compare_mode\":%u}",
            error,info.firmware,info.master_firmware,info.protocol,info.phase_multiplier,info.compare_mode);
        return n<0 || (size_t)n>=capacity ? -1 : 0;
    }
    return fm10k_eye_format(&scan,0,out,capacity);
}
void fm10k_eye_poll(int sw) {
    if (!fm10k_eye_active(&scan) || sw!=target.sw || check_owner()) return;
    if (fmPlatformMgmtTakeSwitchLock(sw)!=FM_OK) return;
    nl_port_scope_status scope=nl_port_scope_get();
    if (scope.tx_id || scope.mask || scope.degraded) fm10k_eye_cancel(&scan,"configuration_changed");
    fm10k_eye_tick(&scan);
    if (fmPlatformMgmtDropSwitchLock(sw)!=FM_OK) scan.restore_failed=true;
    /* A missing original master must not be exposed to queued SDK timers. */
    if(!fm10k_eye_active(&scan) && !target.master_changed) (void)release_exclusive();
    atomic_store_explicit(&poll_active,fm10k_eye_active(&scan),memory_order_relaxed);
}
int fm10k_eye_preempt(int sw) {
    if(check_owner()) return -1;
    if (scan.restore_failed) return -1;
    if (!fm10k_eye_active(&scan)) return 0;
    fm10k_eye_cancel(&scan,"configuration_changed");
    /* Drain the current bounded column before touching port configuration. */
    uint64_t begin=eye_now(NULL);
    for (unsigned tries=0; tries<1000 && fm10k_eye_active(&scan); ++tries) {
        fm10k_eye_poll(sw);
        if (eye_now(NULL)-begin>1000) break;
        if (fm10k_eye_active(&scan)) usleep(1000);
    }
    return fm10k_eye_active(&scan) || scan.restore_failed ? -1 : 0;
}
int fm10k_eye_shutdown(int sw) {
    if(check_owner()) return -1;
    fm10k_eye_cancel(&scan,"service_stopping");
    /* The last board poll may already have stopped. Drain on the owner
     * thread before native teardown, allowing the bounded 15 s column
     * timeout plus firmware restoration rather than abandoning the lock. */
    uint64_t begin=eye_now(NULL);
    for(unsigned n=0;n<22000 && fm10k_eye_active(&scan);++n) {
        fm10k_eye_poll(sw);
        if(eye_now(NULL)-begin>20000) break;
        if(fm10k_eye_active(&scan)) usleep(1000);
    }
    return fm10k_eye_active(&scan) || scan.restore_failed ? -1 : 0;
}
