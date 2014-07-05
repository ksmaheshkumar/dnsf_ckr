#ifndef _DNSF_CKR_ARPSPF_H
#define _DNSF_CKR_ARPSPF_H 1

#include "types.h"
#include <stdlib.h>

int dnsf_ckr_spoof_mac(const char *src_mac, const char *spf_src_ip,
                       const char *dest_mac, const char *dest_ip,
                       const size_t sent_nr, const int secs_out);

#endif
