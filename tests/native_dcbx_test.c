#include "../vendor/netlab/sbin/lldpd/lldp_tlv.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    dcbx_state local = {0}, peer = {0};
    local.enabled = local.pfc_present = local.ets_present = local.app_present = true;
    local.pfc_capability = local.ets_capability = 8; local.pfc_mask = 8;
    const u8 bw[8] = {15,15,14,14,14,14,14,0};
    for (int i = 0; i < 8; i++) { local.priority_tc[i] = (u8)(i == 6 ? 7 : i == 7 ? 6 : i); local.bandwidth[i] = bw[i]; local.tsa[i] = i == 7 ? 0 : 2; }
    local.n_apps = 2;
    local.apps[0] = (dcbx_app){3,5,26}; local.apps[1] = (dcbx_app){6,5,48};
    u8 wire[1500];
    int n = dcbx_append(wire, sizeof(wire), 0, &local);
    assert(n == 75);
    /* Known IEEE wire values, not just a builder/parser round trip. */
    const u8 pfc[] = {0xfe,6,0,0x80,0xc2,11,8,8};
    const u8 app[] = {0xfe,11,0,0x80,0xc2,12,0,0x65,0,26,0xc5,0,48};
    assert(!memcmp(wire+54,pfc,sizeof(pfc)) && !memcmp(wire+62,app,sizeof(app)));
    assert(wire[0] == 0xfe && wire[1] == 25 && wire[5] == 9 && wire[6] == 0);
    assert(wire[7] == 0x01 && wire[8] == 0x23 && wire[9] == 0x45 && wire[10] == 0x76);
    for (int off = 0; off < n; ) {
        int len = (wire[off] & 1) * 256 + wire[off+1];
        dcbx_parse(wire+off+2,len,&peer); off += len+2;
    }
    assert(!peer.malformed && peer.recommendation_present);
    assert(!strcmp(dcbx_compare(&local,&peer),"matched"));
    peer.pfc_willing = peer.ets_willing = true;
    assert(!strcmp(dcbx_compare(&local,&peer),"matched"));
    peer.pfc_mask = 0; assert(!strcmp(dcbx_compare(&local,&peer),"pfc-mismatch")); peer.pfc_mask = 8;
    peer.bandwidth[3] = 20; assert(!strcmp(dcbx_compare(&local,&peer),"ets-mismatch")); peer.bandwidth[3] = 14;
    peer.apps[1].priority = 3; assert(!strcmp(dcbx_compare(&local,&peer),"app-mismatch"));
    dcbx_parse(wire+56,6,&peer); assert(peer.malformed); /* duplicate PFC */
    memset(&peer,0,sizeof(peer)); dcbx_parse(wire+64,10,&peer); assert(peer.malformed); /* partial app */
    memset(&peer,0,sizeof(peer)); dcbx_parse(wire+2,24,&peer); assert(peer.malformed); /* short ETS */
    assert(dcbx_append(wire,74,0,&local) < 0);
    char xml[4096]; assert(dcbx_format_xml(xml,sizeof(xml),"local",&local)>0);
    assert(strstr(xml,"pfc-willing=\"false\"") && strstr(xml,"protocol=\"48\""));
    assert(dcbx_format_xml(xml,16,"local",&local)<0);
    const char *cfg_xml = "<interface><dcbx><enabled>true</enabled><pfc-mask>8</pfc-mask>"
        "<priority-map>0 1 2 3 4 5 7 6</priority-map><bandwidth>15 15 14 14 14 14 14 0</bandwidth>"
        "<tsa-map>2 2 2 2 2 2 2 0</tsa-map><application><selector>5</selector><protocol>26</protocol>"
        "<priority>3</priority></application><application><selector>5</selector><protocol>48</protocol>"
        "<priority>6</priority></application></dcbx></interface>";
    assert(dcbx_load_xml(cfg_xml,cfg_xml+strlen(cfg_xml),&peer));
    assert(!strcmp(dcbx_compare(&local,&peer),"matched"));
    const char *bad = "<interface><dcbx><enabled>true</enabled></dcbx></interface>";
    assert(!dcbx_load_xml(bad,bad+strlen(bad),&peer));
    const char *off = "<interface></interface>";
    assert(dcbx_load_xml(off,off+strlen(off),&peer) && !peer.enabled);

    lldp_config cfg = {0}; cfg.dcbx = local;
    const u8 mac[6] = {2,0,0,0,0,1};
    n = lldp_build_lldpdu(wire,sizeof(wire),mac,"et-0/0/12",&cfg,13);
    assert(n > 75);
    lldp_neighbor neighbor;
    lldp_parse_lldpdu(wire,n,&neighbor,13);
    assert(neighbor.valid && neighbor.rx_port == 13 && neighbor.ttl == 120);
    assert(!strcmp(dcbx_compare(&local,&neighbor.dcbx),"matched"));
    lldp_neighbor table[64] = {0}; int count = 0;
    assert(lldp_neighbor_store(table,&count,&neighbor,100,100000) == 0);
    neighbor.rx_port = 17;
    assert(lldp_neighbor_store(table,&count,&neighbor,100,1) == 1 && count == 2);
    assert(lldp_neighbor_current(&table[0],219) && !lldp_neighbor_current(&table[0],220));
    neighbor.rx_port = 13; neighbor.ttl = 0;
    assert(lldp_neighbor_store(table,&count,&neighbor,101,999999) == 0);
    assert(!table[0].valid && table[1].valid);
    neighbor.rx_port = 21; neighbor.ttl = 120;
    assert(lldp_neighbor_store(table,&count,&neighbor,102,10) == 0 && count == 2);
    for (int len = 0; len < n; len++) {
        lldp_parse_lldpdu(wire,len,&neighbor,13); assert(!neighbor.valid);
    }
    for (int pos = 0; pos < n; ) {
        int type = wire[pos] >> 1, len = (wire[pos]&1)*256 + wire[pos+1];
        if (type == 3) { wire[pos+2] = wire[pos+3] = 0; break; }
        pos += len+2;
    }
    lldp_parse_lldpdu(wire,n,&neighbor,13); assert(neighbor.valid && neighbor.ttl == 0);
    wire[0] = 4; /* First mandatory TLV may not be Port ID. */
    lldp_parse_lldpdu(wire,n,&neighbor,13); assert(!neighbor.valid);
    puts("IEEE DCBX: wire vectors, PFC/ETS/APP policy, malformed packets, bounded buffers and LLDP withdrawal passed");
    return 0;
}
