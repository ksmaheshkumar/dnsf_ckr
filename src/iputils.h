#ifndef _DNSF_CKR_IPUTILS_H
#define _DNSF_CKR_IPUTILS_H 1

#include <sys/types.h>

in_addr_t dnsf_ckr_ip2num(const char *dip, size_t dsize);
int dnsf_ckr_is_valid_ipv4(const char *addr);

#endif
