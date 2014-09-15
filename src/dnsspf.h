/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _DNSF_CKR_DNSSPF_H
#define _DNSF_CKR_DNSSPF_H 1

#include "types.h"
#include <stdlib.h>

typedef enum _dnsf_ckr_action {
    dnsf_ckr_action_none,
    dnsf_ckr_action_repass,
    dnsf_ckr_action_spoof,
    dnsf_ckr_action_forward
}dnsf_ckr_action_t;

dnsf_ckr_action_t dnsf_ckr_proc_ip_packet(const unsigned char *pkt,
                                          const size_t pktsz,
                                          unsigned char **outpkt,
                                          size_t *outpktsz,
                                          dnsf_ckr_realdnstransactions_ctx *transactions,
                                          dnsf_ckr_fakenameserver_ctx *fakenameserver,
                                          dnsf_ckr_gateways_config_ctx *gateways,
                                          const unsigned char src_mac[6],
                                          const unsigned char lo_mac[6],
                                          char *domain_name,
                                          size_t domain_name_sz,
                                          dnsf_ckr_victims_ctx **victim,
                                          dnsf_ckr_hostnames_ctx **hostinfo,
                                          const int dnsspf_ttl,
                                          dnsf_ckr_dnsresolvcache_ctx **dnscache,
                                          const int cache_size);

dnsf_ckr_action_t dnsf_ckr_proc_eth_frame(const unsigned char *frame,
                                          const size_t framesz,
                                          unsigned char **outpkt,
                                          size_t *outpktsz,
                                          dnsf_ckr_realdnstransactions_ctx *transactions);

#endif
