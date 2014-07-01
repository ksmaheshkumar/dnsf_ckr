#include "eth.h"
#include "mem.h"
#include "arp.h"
#include "ip.h"
#include <string.h>

struct dnsf_ckr_ethernet_frame *dnsf_ckr_parse_ethernet_frame(const unsigned char *buf, const size_t bsize) {
    const unsigned char *bp = buf;
    struct dnsf_ckr_ethernet_frame *eth = NULL;
    if (buf == NULL) {
        return NULL;
    }
    eth = (struct dnsf_ckr_ethernet_frame *) dnsf_ckr_getmem(sizeof(struct dnsf_ckr_ethernet_frame));
    memset(eth, 0, sizeof(struct dnsf_ckr_ethernet_frame));
    if (bsize < 14) {
        return NULL;
    }
    eth = (struct dnsf_ckr_ethernet_frame *) dnsf_ckr_getmem(sizeof(struct dnsf_ckr_ethernet_frame));
    memcpy(eth->dest_hw_addr, bp, sizeof(eth->dest_hw_addr));
    bp += sizeof(eth->dest_hw_addr);
    memcpy(eth->src_hw_addr, bp, sizeof(eth->src_hw_addr));
    bp += sizeof(eth->src_hw_addr);
    eth->ether_type = ((unsigned short) (*bp) << 8) | (unsigned short) (*(bp + 1));
    bp += sizeof(eth->ether_type);
    eth->payload = (unsigned char *) dnsf_ckr_getmem(bsize - 14);
    memcpy(eth->payload, bp, bsize - 14);
    eth->payload_size = bsize - 14;
    return eth;
}

unsigned char *dnsf_ckr_mk_ethernet_frame(size_t *bsize, struct dnsf_ckr_ethernet_frame eth) {
    unsigned char *retval = NULL, *rp;
    if (bsize == NULL) {
        return NULL;
    }
    retval = (unsigned char *) dnsf_ckr_getmem(14 + eth.payload_size);
    rp = retval;
    memcpy(rp, eth.dest_hw_addr, 6);
    rp += sizeof(eth.dest_hw_addr);
    memcpy(rp, eth.src_hw_addr, 6);
    rp += sizeof(eth.src_hw_addr);
    *rp = (eth.ether_type & 0xff00) >> 8;
    *(rp+1) = eth.ether_type & 0xff;
    rp += sizeof(eth.ether_type);
    memcpy(rp, eth.payload, eth.payload_size);
    //  forget about FCS... :)
    *bsize = (rp - retval) + eth.payload_size;
    return retval;
}
