#include "sk.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/bpf.h>
#include <sys/types.h>
#include <errno.h>

dnsf_ckr_sk dnsf_ckr_create_arp_socket(const char *iface) {
    char bpfdev[20];
    int devno;
    struct ifreq bound_if;
    dnsf_ckr_sk sk = -1;
    int res;
    for (devno = 0; devno < 255 && sk == -1; devno++) {
        sprintf(bpfdev, "/dev/bpf%d", devno);
        sk = open(bpfdev, O_RDWR);
    }
    if (sk != -1) {
        strncpy(bound_if.ifr_name, iface, sizeof(bound_if.ifr_name)-1);
        if ((res = ioctl(sk, BIOCSETIF, &bound_if)) == -1) {
            res = 1;
            ioctl(sk, BIOCGHDRCMPLT, &res);
            perror("ioctl(BIOCSETIF)");
            close(sk);
            sk = -1;
        }
    }
    return sk;
}
