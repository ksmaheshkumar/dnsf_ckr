/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "udp.h"
#include "mem.h"
#include <string.h>

#define inc_dp if (dp++ > dend) {\
                    free(dgram);\
                    *dsize = 0;\
                    return NULL;\
               }

struct dnsf_ckr_udp_header *dnsf_ckr_parse_udp_dgram(const unsigned char *buf, const size_t bsize) {
    struct dnsf_ckr_udp_header *udph = NULL;
    if (buf == NULL) {
        return NULL;
    }
    udph = (struct dnsf_ckr_udp_header *) dnsf_ckr_getmemory(sizeof(struct dnsf_ckr_udp_header));
    memset(udph, 0, sizeof(struct dnsf_ckr_udp_header));
    if (bsize == 0) {
        return NULL;
    }
    udph->src = (unsigned short)(buf[0] << 8) | (unsigned short)(buf[1]);
    udph->dest = (unsigned short)(buf[2] << 8) | (unsigned short)(buf[3]);
    udph->len = (unsigned short)(buf[4] << 8) | (unsigned short)(buf[5]);
    udph->chsum = (unsigned short)(buf[6] << 8) | (unsigned short)(buf[7]);
    udph->payload_size = bsize - 8;
    if (udph->payload_size > 0) {
        udph->payload = (unsigned char *) dnsf_ckr_getmemory(udph->payload_size);
        memcpy(udph->payload, &buf[8], udph->payload_size);
    } else {
        udph->payload = NULL;
    }
    return udph;
}

unsigned char *dnsf_ckr_mk_udp_dgram(size_t *dsize, const struct dnsf_ckr_udp_header udph) {
    unsigned char *dgram = NULL, *dp, *dend;
    if (dsize == NULL) {
        return NULL;
    }
    *dsize = udph.len;
    dgram = (unsigned char *) dnsf_ckr_getmemory(udph.len);
    dp = dgram;
    dend = dgram + udph.len;
    *dp = (udph.src >> 8);
    inc_dp;
    *dp = (udph.src & 0x00ff);
    inc_dp;
    *dp = (udph.dest >> 8);
    inc_dp;
    *dp = (udph.dest & 0x00ff);
    inc_dp;
    *dp = (udph.len >> 8);
    inc_dp;
    *dp = (udph.len & 0x00ff);
    inc_dp;
    *dp = (udph.chsum >> 8);
    inc_dp;
    *dp = (udph.chsum & 0x00ff);
    inc_dp;
    if (udph.payload_size > 0) {
        memcpy(dp, udph.payload, udph.payload_size);
    }
    return dgram;
}

unsigned short dnsf_ckr_compute_udp_chsum(const unsigned char *buf, const size_t bsize, unsigned long src_addr, unsigned long dest_addr, const unsigned short pseudo_hdr_len) {
    unsigned long sum = 0;
    unsigned char hi, lo;
    size_t b;
    size_t padded_size = bsize + (bsize & 1);
    sum = (src_addr >> 16) +
          (src_addr & 0x0000ffff) +
          (dest_addr >> 16) +
          (dest_addr & 0x0000ffff) + 0x0011 + pseudo_hdr_len;
    for (b = 0; b < padded_size; b += 2) {
        hi = buf[b];
        lo = 0;
        if ((b + 1) < bsize) {
            lo = buf[b + 1];
        }
        sum += (((unsigned short)(hi << 8)) | ((unsigned short)lo));
    }
    while (sum >> 16) {
        sum = (sum & 0x0000ffff) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}
