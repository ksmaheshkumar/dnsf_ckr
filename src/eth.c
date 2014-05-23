#include "eth.h"
#include "mem.h"
#include "arp.h"
#include "ip.h"
#include <string.h>

struct dnsf_ckr_ethernet_frame *dnsf_ckr_parse_ethernet_frame(const char *buf, const size_t bsize) {
    const char *bp = buf;
    struct dnsf_ckr_ethernet_frame *eth = NULL;
    if (eth == NULL) {
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
    memcpy(&eth->ptype, bp, sizeof(eth->ptype));
    bp += sizeof(eth->ptype);
    if (bp < (buf + bsize)) {
        switch (eth->ptype) {
            case ETH_PROTO_TYPE_ARP:
                eth->payload = (unsigned char *)
                        dnsf_ckr_parse_arp_dgram(bp, bsize - 14);
                eth->payload_size = 0;
                break;
            case ETH_PROTO_TYPE_IP:
                eth->payload = (unsigned char *)
                        dnsf_ckr_parse_ip_dgram(bp, bsize - 14);
                if (eth->payload != NULL) {
                    eth->payload_size = ((struct dnsf_ckr_ip_header *)
                                            eth->payload)->len;
                }
                break;
        }
    }
    return eth;
}

unsigned char *dnsf_ckr_mk_ethernet_frame(size_t *bsize, struct dnsf_ckr_ethernet_frame eth) {
    unsigned char *retval = NULL, *rp;
    if (bsize == NULL) {
        return NULL;
    }
    retval = (unsigned char *) dnsf_ckr_getmem(14 + eth.payload_size);
    rp = retval;
    memcpy(rp, eth.dest_hw_addr, sizeof(eth.dest_hw_addr));
    rp += sizeof(eth.dest_hw_addr);
    memcpy(rp, eth.src_hw_addr, sizeof(eth.src_hw_addr));
    rp += sizeof(eth.src_hw_addr);
    memcpy(rp, &eth.ptype, sizeof(eth.ptype));
    rp += sizeof(eth.ptype);
    memcpy(rp, eth.payload, eth.payload_size);
    //  forget about FCS... :)
    return retval;
}
