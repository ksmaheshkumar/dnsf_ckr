#include "udp.h"
#include "mem.h"
#include <string.h>

#define inc_dp if (dp++ > dend) {\
                    free(dgram);\
                    *dsize = 0;\
                    return NULL;\
               }

struct dnsf_ckr_udp_header *dnsf_ckr_parse_udp_dgram(const char *buf, const size_t bsize) {
    struct dnsf_ckr_udp_header *udph = NULL;
    if (udph == NULL || buf == NULL) {
        return NULL;
    }
    udph = (struct dnsf_ckr_udp_header *) dnsf_ckr_getmem(sizeof(struct dnsf_ckr_udp_header));
    memset(udph, 0, sizeof(struct dnsf_ckr_udp_header));
    if (bsize == 0) {
        return NULL;
    }
    udph->src = (unsigned short)(buf[0] << 8) | (unsigned short)(buf[1]);
    udph->dest = (unsigned short)(buf[2] << 8) | (unsigned short)(buf[3]);
    udph->len = (unsigned short)(buf[4] << 8) | (unsigned short)(buf[5]);
    udph->chsum = (unsigned short)(buf[6] << 8) | (unsigned short)(buf[7]);
    udph->payload_size = bsize - 8;
    udph->payload = (unsigned char *) dnsf_ckr_getmem(udph->payload_size);
    memcpy(udph->payload, buf, udph->payload_size);
    return udph;
}

unsigned char *dnsf_ckr_mk_udp_dgram(size_t *dsize, const struct dnsf_ckr_udp_header udph) {
    unsigned char *dgram = NULL, *dp, *dend;
    if (dsize == NULL) {
        return NULL;
    }
    *dsize = udph.len;
    dgram = (unsigned char *) dnsf_ckr_getmem(udph.len);
    dp = dgram;
    dend = dgram + udph.len;
    *dp = (udph.src & 0xff00) >> 8;
    inc_dp;
    *dp = (udph.src & 0x00ff);
    inc_dp;
    *dp = (udph.dest & 0xff00) >> 8;
    inc_dp;
    *dp = (udph.dest & 0x00ff);
    inc_dp;
    *dp = (udph.len & 0xff00) >> 8;
    inc_dp;
    *dp = (udph.len & 0x00ff);
    inc_dp;
    *dp = (udph.chsum & 0xff00) >> 8;
    inc_dp;
    *dp = (udph.chsum & 0x00ff);
    inc_dp;
    if (udph.payload_size) {
        memcpy(dp, udph.payload, udph.payload_size);
    }
    return dgram;
}
