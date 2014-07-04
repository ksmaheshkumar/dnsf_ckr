#include "bpf_io.h"
#include "sk.h"
#include "mem.h"
#include <net/bpf.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

/*
 *
 * INFO(Santiago): In my opinion, bpf really sucks!! Here in this module I intend to make
 *                 the dnsf_ckr able to do all which is needed with only one bpf device.
 *
 *                 FORGET about packet forward I WON'T do it and lose my remaining sanity.
 *                 Divert sockets sucks too!
 *
 */

static dnsf_ckr_sk bpf_fd = -1;

static char bpf_bound_iface[0xff];

static size_t bpf_fd_bsize = 0;

static pthread_mutex_t bpf_dev_mtx = PTHREAD_MUTEX_INITIALIZER;

static dnsf_ckr_bpfio_data_ctx *add_data_to_dnsf_ckr_bpfio_data_ctx(dnsf_ckr_bpfio_data_ctx *bdata, const unsigned char *data, const size_t dsize);

static dnsf_ckr_bpfio_data_ctx *get_dnsf_ckr_bpfio_data_ctx_tail(dnsf_ckr_bpfio_data_ctx *data);

#define new_dnsf_ckr_bpfio_data_ctx(d) ( (d) = (dnsf_ckr_bpfio_data_ctx *) dnsf_ckr_getmem(sizeof(dnsf_ckr_bpfio_data_ctx)),\
                                     (d)->next = NULL, (d)->data = NULL, (d)->dsize = 0 )

int dnsf_ckr_init_bpfio(const char *iface) {
    if (bpf_fd != -1) {
        return 1;
    }
    bpf_fd = dnsf_ckr_create_arp_socket(iface);
    if (bpf_fd != -1) {
        memset(bpf_bound_iface, 0, sizeof(bpf_bound_iface));
        strncpy(bpf_bound_iface, iface, sizeof(bpf_bound_iface) - 1);
        bpf_fd_bsize = get_arp_socket_blen(bpf_fd);
    }
    return (bpf_fd != -1);
}

void dnsf_ckr_fini_bpfio() {
    pthread_mutex_lock(&bpf_dev_mtx);
    if (bpf_fd != -1) {
        dnsf_ckr_close_socket(bpf_fd, bpf_bound_iface);
        memset(bpf_bound_iface, 0, sizeof(bpf_bound_iface));
        bpf_fd = -1;
    }
    pthread_mutex_unlock(&bpf_dev_mtx);
}

dnsf_ckr_bpfio_data_ctx *dnsf_ckr_bpf_read() {
    dnsf_ckr_bpfio_data_ctx *retd = NULL;
    ssize_t bytes_total;
    unsigned char *rawpkt;
    size_t rawpktsz;
    struct bpf_hdr *bpf_buf = NULL, *bpf_pkt;
    char *bpf_buf_p;
    if (bpf_fd == -1) {
        return NULL;
    }
    pthread_mutex_lock(&bpf_dev_mtx);
    bpf_buf = (struct bpf_hdr *) dnsf_ckr_getmem(bpf_fd_bsize);
    memset(bpf_buf, 0, bpf_fd_bsize);
    bytes_total = read(bpf_fd, bpf_buf, bpf_fd_bsize);
    if (bytes_total > 0) {
        bpf_buf_p = (char *)bpf_buf;
        while (bpf_buf_p < ((char *)(bpf_buf + bytes_total))) {
            bpf_pkt = (struct bpf_hdr *)bpf_buf_p;
            rawpkt = ((unsigned char *)bpf_pkt + bpf_pkt->bh_hdrlen);
            rawpktsz = bpf_pkt->bh_datalen;
            if (rawpktsz > 0) {
                retd = add_data_to_dnsf_ckr_bpfio_data_ctx(retd, rawpkt, rawpktsz);
            }
            if (bpf_pkt->bh_hdrlen == 0) break;
            bpf_buf_p += BPF_WORDALIGN(bpf_pkt->bh_hdrlen + bpf_pkt->bh_caplen);
        }
    }
    free(bpf_buf);
    pthread_mutex_unlock(&bpf_dev_mtx);
    return retd;
}

int dnsf_ckr_bpf_write(unsigned char *buffer, const size_t bsize) {
    int retval = -1;
    if (bpf_fd == -1) {
        return -1;
    }
    pthread_mutex_lock(&bpf_dev_mtx);
    retval = write(bpf_fd, buffer, bsize);
    pthread_mutex_unlock(&bpf_dev_mtx);
    return retval;
}

void del_dnsf_ckr_bpfio_data_ctx(dnsf_ckr_bpfio_data_ctx *data) {
    dnsf_ckr_bpfio_data_ctx *p, *t;
    for (p = t = data; t; p = t) {
        t = p->next;
        free(p->data);
        free(p);
    }
}

static dnsf_ckr_bpfio_data_ctx *add_data_to_dnsf_ckr_bpfio_data_ctx(dnsf_ckr_bpfio_data_ctx *bdata, const unsigned char *data, const size_t dsize) {
    dnsf_ckr_bpfio_data_ctx *head = bdata, *p;
    if (head == NULL) {
        new_dnsf_ckr_bpfio_data_ctx(head);
        p = head;
    } else {
        p = get_dnsf_ckr_bpfio_data_ctx_tail(head);
        new_dnsf_ckr_bpfio_data_ctx(p->next);
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

static dnsf_ckr_bpfio_data_ctx *get_dnsf_ckr_bpfio_data_ctx_tail(dnsf_ckr_bpfio_data_ctx *data) {
    dnsf_ckr_bpfio_data_ctx *p;
    for (p = data; p->next; p = p->next);
    return p;
}
