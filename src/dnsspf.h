#ifndef _DNSF_CKR_DNSSPF_H
#define _DNSF_CKR_DNSSPF_H 1

#include "types.h"
#include <stdlib.h>

typedef enum _dnsf_ckr_action {
    dnsf_ckr_action_none,
    dnsf_ckr_action_repass,
    dnsf_ckr_action_spoof
}dnsf_ckr_action_t;

dnsf_ckr_action_t dnsf_ckr_proc_ip_packet(const unsigned char *pkt, const size_t pktsz, unsigned char **outpkt, size_t *outpktsz, dnsf_ckr_realdnstransactions_ctx *transactions, dnsf_ckr_fakenameserver_ctx *fakenameserver, const unsigned char src_mac[6]);

dnsf_ckr_action_t dnsf_ckr_proc_eth_frame(const unsigned char *frame, const size_t framesz, unsigned char **outpkt, size_t *outpktsz, dnsf_ckr_realdnstransactions_ctx *transactions);

#endif
