#include "sk.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/bpf.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

dnsf_ckr_sk dnsf_ckr_create_arp_socket(const char *iface) {
    char bpfdev[20];
    int devno;
    struct ifreq bound_if;
    dnsf_ckr_sk sk = -1, tmp_sk;
    int res;
    for (devno = 0; devno < 255 && sk == -1; devno++) {
        sprintf(bpfdev, "/dev/bpf%d", devno);
        sk = open(bpfdev, O_RDWR | O_SHLOCK);
    }
    if (sk != -1) {
        res = fcntl(sk, F_GETFL);
        fcntl(sk, F_SETFL, res | O_NONBLOCK);
        strncpy(bound_if.ifr_name, iface, sizeof(bound_if.ifr_name) - 1);
        if ((res = ioctl(sk, BIOCSETIF, &bound_if)) == -1) {
            res = 1;
            ioctl(sk, BIOCGHDRCMPLT, &res);
            perror("ioctl(BIOCSETIF)");
            close(sk);
            sk = -1;
        }
        res = 1;
        if ((res = ioctl(sk, BIOCIMMEDIATE, &res)) == -1) {
            perror("");
            close(sk);
            sk = -1;
        }
        tmp_sk = socket(AF_INET, SOCK_DGRAM, 0);
        if ((res = ioctl(tmp_sk, SIOCGIFFLAGS, &bound_if)) == -1) {
            perror("ioctl(SIOCGIFFLAGS)");
        }
        bound_if.ifr_flags |= IFF_PROMISC;
        if ((res = ioctl(tmp_sk, SIOCSIFFLAGS, &bound_if)) == -1) {
            perror("ioctl(SIOCSIFFLAGS)");
        }
        close(tmp_sk);
    }
    return sk;
}

void dnsf_ckr_close_socket(const dnsf_ckr_sk socket, const char *iface) {
    struct ifreq bound_if;
    int res;
    strncpy(bound_if.ifr_name, iface, sizeof(bound_if.ifr_name) - 1);
    res = ioctl(socket, SIOCGIFFLAGS, &bound_if);
    if (res != -1) {
        bound_if.ifr_flags &= ~IFF_PROMISC;
        ioctl(socket, SIOCSIFFLAGS, &bound_if);
    }
    close(socket);
}

int get_arp_socket_blen(dnsf_ckr_sk sk) {
    int value;
    if (ioctl(sk, BIOCGBLEN, &value) == -1) {
        perror("");
        return 0;
    }
    return value;
}

dnsf_ckr_sk dnsf_ckr_create_divert_socket(const unsigned short dv_port) {
    dnsf_ckr_sk sk = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    struct sockaddr_in sk_in;
    /*int opt = 1;*/
    if (sk != -1) {
        /*if (setsockopt(sk, IPPROTO_DIVERT, IP_HDRINCL, &opt, sizeof(opt)) != 0) {
            perror("setsockopt(IP_HDRINCL)");
        }*/
        sk_in.sin_family = PF_INET;
        sk_in.sin_port = htons(dv_port);
        sk_in.sin_addr.s_addr = INADDR_ANY;
        if (bind(sk, (struct sockaddr *)&sk_in, sizeof(sk_in)) == -1) {
            close(sk);
            sk = -1;
        }
    }
    return sk;
}
