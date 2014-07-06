#include "rawsock_io.h"

dnsf_ckr_sockio_data_ctx *dnsf_ckr_sk_read() {
    return NULL;
}

int dnsf_ckr_sk_write(unsigned char *buffer, const size_t bsize) {
    return -1;
}

int dnsf_ckr_init_skio(const char *iface) {
    return 0;
}

void dnsf_ckr_fini_skio() {

}
