#ifndef _DNSF_CKR_NATIVE_ARP_H
#define _DNSF_CKR_NATIVE_ARP_H 1

#include <sys/types.h>

char *dnsf_ckr_get_mac_by_addr(in_addr_t addr, const char *loiface, const int max_tries);

#endif
