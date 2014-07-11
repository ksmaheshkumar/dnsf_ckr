/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _DNSF_CKR_BPF_IO_H
#define _DNSF_CKR_BPF_IO_H 1

#include <stdlib.h>

#include "../sockio.h"

dnsf_ckr_sockio_data_ctx *dnsf_ckr_bpf_read();

int dnsf_ckr_bpf_write(unsigned char *buffer, const size_t bsize);

int dnsf_ckr_init_bpfio(const char *iface);

void dnsf_ckr_fini_bpfio();

#endif
