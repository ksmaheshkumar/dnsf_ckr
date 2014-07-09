#include "rawsock_io.h"
#include "sk.h"
#include <string.h>
#include <pthread.h>

static dnsf_ckr_sk sockfd = -1;

static pthread_mutex_t sock_mtx = PTHREAD_MUTEX_INITIALIZER;

static char sockfd_bound_iface[0xff];

dnsf_ckr_sockio_data_ctx *dnsf_ckr_sk_read() {
    dnsf_ckr_sockio_data_ctx *retval = NULL;
    int bytes_read;
    unsigned char buffer[0xffff];
    pthread_mutex_lock(&sock_mtx);
    bytes_read = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, 0);
    if (bytes_read > 0) {
        retval = add_data_to_dnsf_ckr_sockio_data_ctx(retval, buffer, bytes_read);
    }
    pthread_mutex_unlock(&sock_mtx);
    return retval;
}

int dnsf_ckr_sk_write(unsigned char *buffer, const size_t bsize) {
    int bytes_written = 0;
    pthread_mutex_lock(&sock_mtx);
    bytes_written = sendto(sockfd, buffer, bsize, 0, NULL, 0);
    pthread_mutex_unlock(&sock_mtx);
    return bytes_written;
}

int dnsf_ckr_init_skio(const char *iface) {
    struct timeval tv;
    if (sockfd != -1) {
        return 1;
    }
    memset(sockfd_bound_iface, 0, sizeof(sockfd_bound_iface));
    sockfd = dnsf_ckr_create_linl1sk(iface);
    if (sockfd == -1) {
        return 0;
    }
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    strncpy(sockfd_bound_iface, iface, sizeof(sockfd_bound_iface) - 1);
    return 1;
}

void dnsf_ckr_fini_skio() {
    pthread_mutex_lock(&sock_mtx);
    if (sockfd != -1) {
        dnsf_ckr_close_linl1sk(sockfd, sockfd_bound_iface);
        sockfd = -1;
        memset(sockfd_bound_iface, 0, sizeof(sockfd_bound_iface));
    }
    pthread_mutex_unlock(&sock_mtx);
}
