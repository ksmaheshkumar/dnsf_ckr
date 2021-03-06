/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "ip.h"
#include "mem.h"
#include <string.h>

#define inc_dp if (dp++ > dend) {\
                    free(dgram);\
                    *bsize = 0;\
                    return NULL;\
                }

unsigned short dnsf_ckr_compute_chsum(unsigned char *data, size_t dsize) {
    unsigned int sum = 0;
    unsigned char lo, hi;
    size_t d;
    size_t padded_size = dsize + (dsize & 1);
    for (d = 0; d < padded_size; d += 2) {
        hi = data[d];
        lo = 0;
        if ((d + 1) < dsize) {
            lo = data[d+1];
        }
        sum += ((hi << 8) | lo);
    }
    while (sum >> 16) {
        sum = (sum >> 16) + ((sum << 16) >> 16);
    }
    return ~sum;
}

struct dnsf_ckr_ip_header *dnsf_ckr_parse_ip_dgram(const unsigned char *buf, const size_t bsize) {
    struct dnsf_ckr_ip_header *iph = NULL;
    if (buf == NULL || bsize == 0) {
        return NULL;
    }
    iph = (struct dnsf_ckr_ip_header *) dnsf_ckr_getmemory(sizeof(struct dnsf_ckr_ip_header));
    memset(iph, 0, sizeof(struct dnsf_ckr_ip_header));
    iph->version = (buf[0] & 0xf0) >> 4;
    if (iph->version != 4) {
        iph->version = 0;
        free(iph);
        return NULL;
    }
    iph->ihl = buf[0] & 0x0f;
    iph->tos = buf[1];
    iph->len = (unsigned short)(buf[2] << 8) | (unsigned short)(buf[3]);
    iph->id = (unsigned short)(buf[4] << 8) | (unsigned short)(buf[5]);
    iph->flags = (buf[6] & 0xe0) >> 4;
    iph->fragoff = (unsigned short)(buf[6] & 0x1f) << 8 | (unsigned short)(buf[7]);
    iph->ttl = buf[8];
    iph->proto = buf[9];
    iph->chsum = (unsigned short)(buf[10] << 8) | (unsigned short)(buf[11]);
    iph->src = (unsigned int)(buf[12] << 24) |
               (unsigned int)(buf[13] << 16) |
               (unsigned int)(buf[14] <<  8) |
               (unsigned int)(buf[15]);
    iph->dest = (unsigned int)(buf[16] << 24) |
                (unsigned int)(buf[17] << 16) |
                (unsigned int)(buf[18] <<  8) |
                (unsigned int)(buf[19]);
    iph->opt = NULL;
    iph->opt_size = 0;
    iph->payload_size = iph->len - 20;
    if (iph->payload_size > 0) {
        iph->payload = (unsigned char *) dnsf_ckr_getmemory(iph->payload_size);
        memcpy(iph->payload, &buf[20], iph->payload_size % bsize);
    } else {
        iph->payload = NULL;
    }
    return iph;
}

unsigned char *dnsf_ckr_mk_ip_dgram(size_t *bsize, const struct dnsf_ckr_ip_header iph) {
    unsigned char *dgram = NULL, *dp, *dend;
    if (bsize == NULL) {
        return NULL;
    }
    dgram = (unsigned char *) dnsf_ckr_getmemory(iph.len);
    *bsize = iph.len;
    dend = dgram + iph.len;
    dp = dgram;
    *dp = (iph.version << 4) | iph.ihl;
    inc_dp;
    *dp = iph.tos;
    inc_dp;
    *dp = (iph.len >> 8);
    inc_dp;
    *dp = (iph.len & 0x00ff);
    inc_dp;
    *dp = (iph.id >> 8);
    inc_dp;
    *dp = (iph.id & 0x00ff);
    inc_dp;
    *dp = (iph.flags << 5) | (iph.fragoff & 0x1f00);
    inc_dp;
    *dp = (iph.fragoff & 0x00ff);
    inc_dp;
    *dp = iph.ttl;
    inc_dp;
    *dp = iph.proto;
    inc_dp;
    *dp = (iph.chsum >> 8);
    inc_dp;
    *dp = (iph.chsum & 0x00ff);
    inc_dp;
    *dp = (iph.src >> 24);
    inc_dp;
    *dp = (iph.src & 0x00ff0000) >> 16;
    inc_dp;
    *dp = (iph.src & 0x0000ff00) >> 8;
    inc_dp;
    *dp = (iph.src & 0x000000ff);
    inc_dp;
    *dp = (iph.dest >> 24);
    inc_dp;
    *dp = (iph.dest & 0x00ff0000) >> 16;
    inc_dp;
    *dp = (iph.dest & 0x0000ff00) >> 8;
    inc_dp;
    *dp = (iph.dest & 0x000000ff);
    inc_dp;
    if (iph.payload_size > 0) {
        memcpy(dp, iph.payload, iph.payload_size);
    }
    *bsize = dp - dgram + iph.payload_size;
    return dgram;
}

unsigned char *dnsf_ckr_addr2byte(const char *addr, size_t len) {
    unsigned char *retval = (unsigned char *) dnsf_ckr_getmemory(len + 1), *r;
    char oct[20];
    size_t a, o;
    memset(retval, 0, len);
    r = retval;
    for (a = o = 0; addr[a] != 0; a++, o++) {
        if (addr[a] == '.' || addr[a+1] == 0) {
            if (addr[a+1] == 0) {
                oct[o++] = addr[a];
            }
            oct[o] = 0;
            *r = (unsigned char)atoi(oct);
            r++;
            o = -1;
        } else {
            oct[o] = addr[a];
        }
    }
    return retval;
}
