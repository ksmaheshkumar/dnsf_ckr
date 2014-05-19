#ifndef _DNSF_CKR_UDP_H
#define _DNSF_CKR_UDP_H 1

#include <stdlib.h>

struct dnsf_ckr_udp_header {
    unsigned short src;
    unsigned short dest;
    unsigned short len;
    unsigned short chsum;
    unsigned char *payload;
    size_t payload_size;
};

void dnsf_ckr_parse_udp_dgram(struct dnsf_ckr_udp_header *udph, const char *buf, size_t bsize);

unsigned char *dnsf_ckr_mk_udp_dgram(size_t *dsize, const struct dnsf_ckr_udp_header udph);

#endif
