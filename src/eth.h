#ifndef _DNSF_CKR_ETH_H
#define _DNSF_CKR_ETH_H 1

#include <stdlib.h>

#define ETHER_TYPE_ARP      0x0806
#define ETHER_TYPE_IP       0x0800

struct dnsf_ckr_ethernet_frame {
    unsigned char dest_hw_addr[6];
    unsigned char src_hw_addr[6];
    unsigned short ether_type;
    unsigned char *payload;
    size_t payload_size;
};

struct dnsf_ckr_ethernet_frame *dnsf_ckr_parse_ethernet_frame(const char *buf, const size_t bsize);

unsigned char *dnsf_ckr_mk_ethernet_frame(size_t *bsize, struct dnsf_ckr_ethernet_frame eth);

#endif
