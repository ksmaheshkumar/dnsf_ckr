#ifndef _DNSF_CKR_RAWSOCK_IO_H
#define _DNSF_CKR_RAWSOCK_IO_H 1

#include <stdlib.h>

#include "../sockio.h"

dnsf_ckr_sockio_data_ctx *dnsf_ckr_sk_read();

int dnsf_ckr_sk_write(unsigned char *buffer, const size_t bsize);

int dnsf_ckr_init_skio(const char *iface);

void dnsf_ckr_fini_skio();

#endif
