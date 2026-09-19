#include "fm10k_eye_scan.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint64_t time;
    unsigned index, columns, primes, calls, compare, timer_words, prepared, restored, dfe_flags;
    unsigned prepare_wait, counter_reads, counter_resets, pi_shutdowns;
    bool paused, pending, no_data, no_signal, pause_error, resume_error, timeout_sample, prepare_error, restore_error;
} fake;
static fake f;
static fm10k_eye_scan scan;
static uint64_t now(void *ctx) { return ((fake *)ctx)->time; }
static int serdes(void *ctx, unsigned irq, unsigned data, uint32_t *out) {
    fake *v=ctx; ++v->calls; *out=irq&255;
    if (irq==0x126) { *out=v->dfe_flags; return 0; }
    if (irq==0x0103) v->timer_words=data;
    if (irq==0x0203) v->timer_words|=data<<16;
    if (irq==0x0a) {
        v->paused=data==0;
        if (!data && v->pause_error) return -1;
        if (data==15 && v->resume_error) return -1;
    }
    if (irq==3) v->compare=data&0x770;
    if (irq==0x18) { assert(data==3); v->counter_reads=0; }
    if (irq==0x1a) { assert(data==0); ++v->counter_reads; *out=0; }
    if (irq==0x17) { assert(data==0 && v->counter_reads==2); ++v->counter_resets; }
    if (irq==0x0f) { assert(data==0x100 && v->counter_resets); ++v->pi_shutdowns; }
    return 0;
}
static int master(void *ctx, unsigned data, uint32_t *out, bool wait) {
    fake *v=ctx; ++v->calls; *out=0x2f;
    if (!wait) {
        assert((data&0xf000)==0xb000 || data==0xc000);
        assert(v->compare==0x100 && v->paused);
        v->pending=true;
        if (data==0xc000) ++v->primes;
        else { assert(v->primes==1); ++v->columns; }
    } else if (data==8) *out=0xfff9;
    return 0;
}
static int read_reg(void *ctx, unsigned reg, uint32_t *out) {
    fake *v=ctx; ++v->calls;
    if (reg==8) { *out=v->no_data ? 0x8000 : 0x00000001; return 0; }
    if (reg==0x12) { *out=v->no_data?0:v->index; return 0; }
    unsigned n=(v->index-1)*4+(reg==0x13?1:3);
    *out=v->timeout_sample?0xffffffff:(n<<16)|(n+1);
    return 0;
}
static int write_reg(void *ctx, unsigned reg, uint32_t data) {
    fake *v=ctx; ++v->calls; if (reg==0x11) v->index=data; return 0;
}
static int cmp(void *ctx, uint32_t *out) { *out=((fake *)ctx)->compare; return 0; }
static int signal_ok(void *ctx) { return ((fake *)ctx)->no_signal?-1:0; }
static int prepare(void *ctx) {
    fake *v=ctx; assert(v->paused); ++v->prepared; v->no_signal=false;
    if(v->prepare_wait) { --v->prepare_wait; return 1; }
    return v->prepare_error?-1:0;
}
static int restore(void *ctx) {
    fake *v=ctx; assert(v->paused); ++v->restored;
    return v->restore_error?-1:0;
}
static const char *id="123456789abcdef0123456789abcdef0";
static fm10k_eye_target target={.sbus=2,.phase_multiplier=2,.firmware=0x10550001,
    .master_firmware=0x101a0001,.protocol=0,.compare_mode=0x200,.port=1,.epl=0,.lane=0,.speed_mbps=10000};
static fm10k_eye_io io={.context=&f,.serdes=serdes,.master=master,.read=read_reg,.write=write_reg,
    .compare=cmp,.signal=signal_ok,.prepare=prepare,.restore=restore,.now=now};
static void reset(void) { memset(&f,0,sizeof(f)); memset(&scan,0,sizeof(scan)); f.time=1000; f.compare=0x200; }
static void tick(void) { f.time+=10; fm10k_eye_tick(&scan); }
static void start(void) { assert(!fm10k_eye_start(&scan,&io,&target,id,16,8,100000,1700000000)); }
int main(void) {
    reset();
    assert(fm10k_eye_start(&scan,&io,&target,"bad",16,8,100000,0)<0 && !f.calls);
    fm10k_eye_target old=target; old.firmware=0x10480001;
    assert(fm10k_eye_start(&scan,&io,&old,id,16,8,100000,0)<0 && !f.calls);
    start(); assert(f.paused);
    assert(fm10k_eye_start(&scan,&io,&target,id,16,8,100000,0)<0);
    for (int n=0; fm10k_eye_active(&scan) && n<1000; ++n) tick();
    assert(scan.state==EYE_COMPLETE && scan.columns_done==33 && scan.y_points==32);
    assert(scan.restored && !f.paused && f.compare==0x200);
    assert(f.counter_resets==1 && f.pi_shutdowns==1);
    assert(f.timer_words==5000 && f.primes==1 && f.columns==33 && scan.phase_center==-7);
    for (unsigned x=0;x<33;++x) for(unsigned y=0;y<32;++y) assert(scan.errors[x][y]==y+1);
    char out[8192]; assert(!fm10k_eye_format(&scan,29,out,sizeof(out)) && strstr(out,"\"complete\""));
    assert(fm10k_eye_format(&scan,34,out,sizeof(out))<0 && fm10k_eye_format(&scan,0,out,16)<0);
    assert(fm10k_eye_decode_count(0x2000)==8192 && fm10k_eye_decode_count(0x1fff)==8191);
    assert(fm10k_eye_decode_count(0xffff)==UINT32_MAX);
    reset(); start(); tick(); tick(); tick(); assert(scan.column_pending && !scan.priming);
    fm10k_eye_cancel(&scan,"user_cancelled"); tick();
    assert(scan.state==EYE_CANCELLED && scan.restored && scan.columns_done==1 && !f.paused);
    reset(); start(); tick(); tick(); tick(); f.no_data=true; tick();
    assert(!scan.columns_done && scan.errors[0][0]==0);
    f.time+=16000; fm10k_eye_tick(&scan);
    assert(scan.state==EYE_FAILED && scan.restore_failed && !scan.columns_done);
    assert(fm10k_eye_start(&scan,&io,&target,id,16,8,100000,0)<0);
    reset(); f.pause_error=true; start();
    assert(scan.state==EYE_FAILED && scan.restored && !f.paused && !f.counter_resets && !f.pi_shutdowns);
    reset(); start(); f.resume_error=true; fm10k_eye_cancel(&scan,"user_cancelled"); tick();
    assert(scan.state==EYE_FAILED && scan.restore_failed);
    reset(); start(); tick(); tick(); f.no_signal=true; tick();
    assert(scan.state==EYE_FAILED && !scan.columns_done && scan.restored);
    reset(); start(); tick(); tick(); tick(); f.timeout_sample=true; tick();
    assert(scan.state==EYE_FAILED && !scan.columns_done && scan.restored && !strcmp(scan.error,"sample_timeout"));
    reset(); start(); tick(); fm10k_eye_cancel(&scan,"user_cancelled"); tick();
    assert(scan.state==EYE_CANCELLED && scan.restored && !scan.columns_done);
    reset(); target.internal_loopback=true; f.no_signal=true; f.dfe_flags=0x291;
    start(); tick(); assert(f.prepared==1 && f.paused);
    for(int n=0;fm10k_eye_active(&scan) && n<1000;++n) tick();
    assert(scan.state==EYE_COMPLETE && scan.restored && f.restored==1 && !f.paused);
    assert(!fm10k_eye_format(&scan,0,out,sizeof(out)) && strstr(out,"internal_prbs31_loopback"));
    reset(); f.prepare_error=true; start(); tick();
    assert(scan.state==EYE_FAILED && scan.restored && f.restored==1 && !f.paused);
    reset(); f.prepare_wait=3; start(); tick(); tick();
    assert(scan.state==EYE_PREPARING && scan.prepared && !scan.preparation_done && !f.columns);
    fm10k_eye_cancel(&scan,"user_cancelled"); tick();
    assert(scan.state==EYE_CANCELLED && scan.restored && f.restored==1 && !f.paused);
    assert(!f.counter_resets && !f.pi_shutdowns);
    reset(); start(); tick(); f.restore_error=true; fm10k_eye_cancel(&scan,"user_cancelled"); tick();
    assert(scan.state==EYE_FAILED && scan.restore_failed && f.restored==1 && !f.paused);
    target.internal_loopback=false;
    puts("eye scan: full matrix, raw counts, timeouts, cancellations, firmware guards and restoration passed");
}
