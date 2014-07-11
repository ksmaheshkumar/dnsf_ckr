/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "arpspf.h"
#include "arp.h"
#include "ip.h"
#include "eth.h"
#include "sockio.h"
#include <string.h>
#include <unistd.h>

int dnsf_ckr_spoof_mac(const char *src_mac, const char *spf_src_ip,
                       const char *dest_mac, const char *dest_ip,
                       const size_t sent_nr, const int secs_out) {
    struct dnsf_ckr_ethernet_frame eth;
    struct dnsf_ckr_arp_header arp_packet;
    unsigned char *rawpkt;
    size_t rawpktsz;
    int res;
    arp_packet.hwtype = ARP_HW_TYPE_ETHERNET;
    arp_packet.ptype = ARP_PROTO_TYPE_IP;
    arp_packet.hw_addr_len = 6;
    arp_packet.pt_addr_len = 4;
    arp_packet.opcode = ARP_OPCODE_REPLY;
    arp_packet.src_hw_addr = dnsf_ckr_mac2byte(src_mac, 6);
    arp_packet.src_pt_addr = dnsf_ckr_addr2byte(spf_src_ip, 4);
    arp_packet.dest_hw_addr = dnsf_ckr_mac2byte(dest_mac, 6);
    arp_packet.dest_pt_addr = dnsf_ckr_addr2byte(dest_ip, 4);
    eth.payload = dnsf_ckr_mk_arp_dgram(&eth.payload_size, arp_packet);
    eth.ether_type = ETHER_TYPE_ARP;
    memcpy(eth.dest_hw_addr, arp_packet.dest_hw_addr, 6);
    memcpy(eth.src_hw_addr, arp_packet.src_hw_addr, 6);
    rawpkt = dnsf_ckr_mk_ethernet_frame(&rawpktsz, eth);
    res = dnsf_ckr_sock_write(rawpkt, rawpktsz);
    //usleep(secs_out);
    free(arp_packet.src_hw_addr);
    free(arp_packet.src_pt_addr);
    free(arp_packet.dest_hw_addr);
    free(arp_packet.dest_pt_addr);
    free(eth.payload);
    free(rawpkt);
    return 1;
}
