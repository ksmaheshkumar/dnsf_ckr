#ifndef _DNSF_CKR_SK_H
#define _DNSF_CKR_SK_H 1

#include "types.h"

dnsf_ckr_sk dnsf_ckr_create_arp_socket(const char *iface);
dnsf_ckr_sk dnsf_ckr_create_divert_socket(const unsigned short dv_port);
void dnsf_ckr_close_socket(const dnsf_ckr_sk socket, const char *iface);
int get_arp_socket_blen(dnsf_ckr_sk sk);

#endif
