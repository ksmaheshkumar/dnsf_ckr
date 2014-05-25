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
    memcpy(&eth->ether_type, bp, sizeof(eth->ether_type));
    bp += sizeof(eth->ether_type);
    if (bp < (buf + bsize)) {
        switch (eth->ether_type) {
            case ETHER_TYPE_ARP:
                eth->payload = (unsigned char *)
                        dnsf_ckr_parse_arp_dgram(bp, bsize - 14);
                eth->payload_size = 0;
                break;
            case ETHER_TYPE_IP:
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
    memcpy(rp, eth.dest_hw_addr, 6);//sizeof(eth.dest_hw_addr));
    rp += sizeof(eth.dest_hw_addr);
    memcpy(rp, eth.src_hw_addr, 6);//sizeof(eth.src_hw_addr));
    rp += sizeof(eth.src_hw_addr);
    //memcpy(rp, &eth.ether_type, sizeof(eth.ether_type));
    *rp = (eth.ether_type & 0xff00) >> 8;
    *(rp+1) = eth.ether_type & 0xff;
    rp += sizeof(eth.ether_type);
    memcpy(rp, eth.payload, eth.payload_size);
    //  forget about FCS... :)
    *bsize = rp - retval + eth.payload_size;
    return retval;
}
