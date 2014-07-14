/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "sockio.h"
#include "mem.h"
#include <string.h>

static dnsf_ckr_sockio_data_ctx *get_dnsf_ckr_sockio_data_ctx_tail(dnsf_ckr_sockio_data_ctx *data);

static dnsf_ckr_sockio_data_ctx *get_dnsf_ckr_sockio_data_ctx_tail(dnsf_ckr_sockio_data_ctx *data);

#define new_dnsf_ckr_sockio_data_ctx(d) ( (d) = (dnsf_ckr_sockio_data_ctx *) dnsf_ckr_getmem(sizeof(dnsf_ckr_sockio_data_ctx)),\
                                     (d)->next = NULL, (d)->data = NULL, (d)->dsize = 0 )

int dnsf_ckr_init_sockio(const char *iface) {
#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD
    return dnsf_ckr_init_bpfio(iface);
#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX
    return dnsf_ckr_init_skio(iface);
#endif
    return -1;
}

void dnsf_ckr_fini_sockio() {
#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD
    dnsf_ckr_fini_bpfio();
#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX
    dnsf_ckr_fini_skio();
#endif
}

dnsf_ckr_sockio_data_ctx *dnsf_ckr_sock_read() {
#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD
    return dnsf_ckr_bpf_read();
#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX
    return dnsf_ckr_sk_read();
#endif
    return NULL;
}

int dnsf_ckr_sock_write(unsigned char *buffer, const size_t bsize) {
#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD
    return dnsf_ckr_bpf_write(buffer, bsize);
#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX
    return dnsf_ckr_sk_write(buffer, bsize);
#endif
    return -1;
}

void del_dnsf_ckr_sockio_data_ctx(dnsf_ckr_sockio_data_ctx *data) {
    dnsf_ckr_sockio_data_ctx *p, *t;
    for (p = t = data; t; p = t) {
        t = p->next;
        free(p->data);
        free(p);
    }
}

dnsf_ckr_sockio_data_ctx *add_data_to_dnsf_ckr_sockio_data_ctx(dnsf_ckr_sockio_data_ctx *bdata, const unsigned char *data, const size_t dsize) {
    dnsf_ckr_sockio_data_ctx *head = bdata, *p;
    if (head == NULL) {
        new_dnsf_ckr_sockio_data_ctx(head);
        p = head;
    } else {
        p = get_dnsf_ckr_sockio_data_ctx_tail(head);
        new_dnsf_ckr_sockio_data_ctx(p->next);
        p = p->next;
    }
    p->data = (unsigned char *) dnsf_ckr_getmem(dsize + 1);
    memset(p->data, 0, dsize + 1);
    if (dsize > 0) {
        memcpy(p->data, data, dsize);
    }
    p->dsize = dsize;
    return head;
}

static dnsf_ckr_sockio_data_ctx *get_dnsf_ckr_sockio_data_ctx_tail(dnsf_ckr_sockio_data_ctx *data) {
    dnsf_ckr_sockio_data_ctx *p;
    for (p = data; p->next; p = p->next);
    return p;
}
