/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _DNSF_CKR_SOCKIO_H
#define _DNSF_CKR_SOCKIO_H 1

#include "types.h"

typedef struct _dnsf_ckr_sockio_data {
    unsigned char *data;
    size_t dsize;
    struct _dnsf_ckr_sockio_data *next;
}dnsf_ckr_sockio_data_ctx;

#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD

#include "freebsd/bpf_io.h"

#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX

#include "linux/rawsock_io.h"

#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_WINDOWS

#include "windows/windivert_io.h"

#endif

dnsf_ckr_sockio_data_ctx *add_data_to_dnsf_ckr_sockio_data_ctx(dnsf_ckr_sockio_data_ctx *bdata, const unsigned char *data, const size_t dsize);

dnsf_ckr_sockio_data_ctx *dnsf_ckr_sock_read();

void del_dnsf_ckr_sockio_data_ctx(dnsf_ckr_sockio_data_ctx *data);

int dnsf_ckr_sock_write(unsigned char *buffer, const size_t bsize);

int dnsf_ckr_init_sockio(const char *iface);

void dnsf_ckr_fini_sockio();

#endif
