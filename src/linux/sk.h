#ifndef _DNSF_CKR_SK_H
#define _DNSF_CKR_SK_H 1

#include "../types.h"

dnsf_ckr_sk dnsf_ckr_create_linl1sk(const char *iface);
void dnsf_ckr_close_linl1sk(const dnsf_ckr_sk socket, const char *iface);

#endif
