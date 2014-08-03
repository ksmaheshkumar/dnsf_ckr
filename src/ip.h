/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _DNSF_CKR_IP_H
#define _DNSF_CKR_IP_H 1

#include <stdlib.h>

struct dnsf_ckr_ip_header {
    unsigned char version;
    unsigned char ihl;
    unsigned char tos;
    unsigned short len;
    unsigned short id;
    unsigned char flags;
    unsigned short fragoff;
    unsigned char ttl;
    unsigned char proto;
    unsigned short chsum;
    unsigned int src;
    unsigned int dest;
    unsigned char *opt;
    size_t opt_size;
    unsigned char *payload;
    size_t payload_size;
};

unsigned short dnsf_ckr_compute_chsum(unsigned char *data, size_t dsize);

struct dnsf_ckr_ip_header *dnsf_ckr_parse_ip_dgram(const unsigned char *buf, const size_t bsize);

unsigned char *dnsf_ckr_mk_ip_dgram(size_t *bsize, const struct dnsf_ckr_ip_header iph);

unsigned char *dnsf_ckr_addr2byte(const char *addr, size_t len);

#endif
