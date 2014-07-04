#ifndef _DNSF_CKR_BPF_IO_H
#define _DNSF_CKR_BPF_IO_H

#include <stdlib.h>

typedef struct _dnsf_ckr_bpfio_data {
    unsigned char *data;
    size_t dsize;
    struct _dnsf_ckr_bpfio_data *next;
}dnsf_ckr_bpfio_data_ctx;

dnsf_ckr_bpfio_data_ctx *dnsf_ckr_bpf_read();

void del_dnsf_ckr_bpfio_data_ctx(dnsf_ckr_bpfio_data_ctx *data);

int dnsf_ckr_bpf_write(unsigned char *buffer, const size_t bsize);

int dnsf_ckr_init_bpfio(const char *iface);

void dnsf_ckr_fini_bpfio();

#endif
