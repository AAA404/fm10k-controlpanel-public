#define FM10K_SAMPLING_FIXTURE_ONLY
#include "native_sampling_test.c"
#include "fm10k_monitor.h"

static int ambiguous(void *ctx,uint8_t addr,int reg,const uint8_t *in,size_t n) {
    int rc=write_bytes(ctx,addr,reg,in,n);
    return addr==0x40 && reg==127 && *in==1 ? FM10K_IO : rc;
}
static void power_reset(void) {
    reset();
    for (int mpo=1;mpo<=2;++mpo) for(int c=0;c<12;++c) {
        unsigned raw=c?0x1200+c:0;
        int reg=206+(11-c)*2;
        f.registers[mpo][0x40][reg]=(uint8_t)(raw>>8);
        f.registers[mpo][0x40][reg+1]=(uint8_t)raw;
    }
}
int main(void) {
    fm10k_bus b={.context=&f,.read=read_bytes,.write=write_bytes,.enter=enter,.leave=leave,.delay_ms=delay};
    fm10k_obt_power_sample p;
    power_reset(); assert(!fm10k_obt_rx_power_read(&b,1,&p) && p.valid);
    assert(p.raw[0]==0 && p.raw[1]==0x1201 && p.raw[11]==0x120b);
    assert(f.mux==4 && !f.locked && f.registers[1][0x40][127]==0);
    int transfers=f.transfers;
    for(int n=1;n<=transfers;++n) {
        power_reset(); f.fail_at=n;
        assert(fm10k_obt_rx_power_read(&b,2,&p)!=0 && !p.valid && !f.locked);
    }
    power_reset(); b.write=ambiguous;
    assert(fm10k_obt_rx_power_read(&b,1,&p)!=0 && !p.valid && f.registers[1][0x40][127]==0 && f.mux==4);
    b.write=write_bytes;
    power_reset(); f.registers[1][0x40][2]=1;
    assert(!fm10k_obt_rx_power_read(&b,1,&p) && !p.valid && p.not_ready && f.mux==4);
    power_reset(); f.drop_page=1;
    assert(fm10k_obt_rx_power_read(&b,1,&p)!=0 && !p.valid && !f.locked);
    power_reset(); fm10k_monitor m; fm10k_monitor_init(&m,&b);
    static const uint8_t captured_identity[96] = {0x00,0xd8,0x33,0x80,0x46,0x0c,0xff,0x42,0x68,0x07,0xd0,0xff,0x34,0x70,0x2a,0x08,0xaa,0x28,0x01,0x00,0x4f,0x3e,0x00,0x00,0x46,0x43,0x49,0x20,0x4d,0x65,0x72,0x67,0x65,0x4f,0x70,0x74,0x69,0x63,0x73,0x20,0x00,0x0a,0x0d,0x31,0x30,0x31,0x32,0x34,0x35,0x38,0x38,0x2d,0x32,0x34,0x41,0x20,0x20,0x20,0x20,0x41,0x33,0x4f,0x46,0x31,0x37,0x32,0x34,0x2d,0x30,0x30,0x37,0x32,0x38,0x20,0x20,0x20,0x20,0x32,0x30,0x31,0x37,0x30,0x36,0x31,0x36,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x20,0x6a};
    uint8_t *id=m.identity[0]; memcpy(id,captured_identity,sizeof(captured_identity));
    m.identity_valid[0]=m.identity_fresh[0]=true; m.identity_sample_ms[0]=1000; m.identity_at[0]=100;
    m.fan_due=5000; m.obt_due[1]=5000;
    assert(!fm10k_monitor_step(&m,1000,100));
    char out[16384]; assert(fm10k_monitor_format(&m,1000,100,out,sizeof(out))>0);
    assert(strstr(out,"\"rx_power_quality\":\"valid\"") && strstr(out,"\"tx_power_quality\":\"unsupported\""));
    assert(strstr(out,"\"channel\":0,\"raw\":0,\"microwatts\":0.0,\"dbm\":null"));
    assert(strstr(out,"\"channel\":1,\"raw\":4609,\"microwatts\":460.9"));
    assert(fm10k_monitor_format(&m,20000,119,out,sizeof(out))>0 && strstr(out,"\"rx_power_quality\":\"stale\""));
    id[95]^=1; assert(fm10k_monitor_format(&m,1000,100,out,sizeof(out))>0 && strstr(out,"\"rx_power_quality\":\"unqualified\""));
    puts("CXP optical power: endian, lane mapping, zero, capability, checksum, stale and failed transfers passed");
}
