/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
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

struct dnsf_ckr_udp_header *dnsf_ckr_parse_udp_dgram(const unsigned char *buf, const size_t bsize);

unsigned char *dnsf_ckr_mk_udp_dgram(size_t *dsize, const struct dnsf_ckr_udp_header udph);

unsigned short dnsf_ckr_compute_udp_chsum(const unsigned char *buf, const size_t bsize, unsigned long src_addr, unsigned long dest_addr, const unsigned short pseudo_hdr_len);

#endif
