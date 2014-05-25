#include "ip.h"
#include "mem.h"
#include <string.h>

#define inc_dp if (dp++ > dend) {\
                    free(dgram);\
                    *bsize = 0;\
                    return NULL;\
                }

unsigned short dnsf_ckr_compute_chsum(unsigned char *data, size_t dsize) {
    unsigned long sum = 0;
    unsigned char lo, hi;
    size_t d;
    for (d = 0; d < dsize; d += 2) {
        hi = data[d];
        lo = 0;
        if ((d + 1) < dsize) {
            lo = data[d+1];
        }
        sum += ((hi << 8) | lo);
    }
    while (sum >> 16) {
        sum = (sum >> 16) | ((sum << 16) >> 16);
    }
    return (~sum);
}

struct dnsf_ckr_ip_header *dnsf_ckr_parse_ip_dgram(const char *buf, const size_t bsize) {
    struct dnsf_ckr_ip_header *iph = NULL;
    if (iph == NULL || buf == NULL) {
        return NULL;
    }
    iph = (struct dnsf_ckr_ip_header *) dnsf_ckr_getmem(sizeof(struct dnsf_ckr_ip_header));
    memset(iph, 0, sizeof(struct dnsf_ckr_ip_header));
    if (bsize == 0) {
        return NULL;
    }
    iph->version = (buf[0] & 0xf0) >> 4;
    if (iph->version != 4) {
        iph->version = 0;
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
    iph->src = (unsigned long)(buf[12] << 24) |
               (unsigned long)(buf[13] << 16) |
               (unsigned long)(buf[14] <<  8) |
               (unsigned long)(buf[15]);
    iph->dest = (unsigned long)(buf[16] << 24) |
                (unsigned long)(buf[17] << 16) |
                (unsigned long)(buf[18] <<  8) |
                (unsigned long)(buf[19]);
    iph->opt = NULL;
    iph->opt_size = 0;
    iph->payload_size = iph->len - 20;
    if (iph->payload_size > 0) {
        iph->payload = (unsigned char *) dnsf_ckr_getmem(iph->payload_size);
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
    dgram = (unsigned char *) dnsf_ckr_getmem(iph.len);
    *bsize = iph.len;
    dend = dgram + iph.len;
    dp = dgram;
    *dp = (iph.version << 4) | iph.ihl;
    inc_dp;
    *dp = iph.tos;
    inc_dp;
    *dp = (iph.len & 0xff00) >> 8;
    inc_dp;
    *dp = (iph.len & 0x00ff);
    inc_dp;
    *dp = (iph.id & 0xff00) >> 8;
    inc_dp;
    *dp = (iph.id & 0x00ff);
    *dp = (iph.flags << 5) | (iph.fragoff & 0x1f00);
    inc_dp;
    *dp = (iph.fragoff & 0x00ff);
    inc_dp;
    *dp = iph.ttl;
    inc_dp;
    *dp = (iph.chsum & 0xff00) >> 8;
    inc_dp;
    *dp = (iph.chsum & 0x00ff);
    inc_dp;
    *dp = (iph.src & 0xff000000) >> 24;
    inc_dp;
    *dp = (iph.src & 0x00ff0000) >> 16;
    inc_dp;
    *dp = (iph.src & 0x0000ff00) >> 8;
    inc_dp;
    *dp = (iph.src & 0x000000ff);
    inc_dp;
    *dp = (iph.dest & 0xff000000) >> 24;
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
    unsigned char *retval = (unsigned char *) dnsf_ckr_getmem(len + 1), *r;
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
