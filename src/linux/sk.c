/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "sk.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>

static int dnsf_ckr_get_iface_index(const char *iface);

static int dnsf_ckr_get_iface_index(const char *iface) {
    struct ifreq ifr;
    dnsf_ckr_sk sockfd;
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        return -1;
    }
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) != 0) {
        ifr.ifr_ifindex = -1;
    }
    close(sockfd);
    return ifr.ifr_ifindex;
}

dnsf_ckr_sk dnsf_ckr_create_linl1sk(const char *iface) {
    dnsf_ckr_sk sk = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    struct sockaddr_ll sll;
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = dnsf_ckr_get_iface_index(iface);
    if (bind(sk, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        dnsf_ckr_close_linl1sk(sk, iface);
        return -1;
    }
    return sk;
}

void dnsf_ckr_close_linl1sk(const dnsf_ckr_sk socket, const char *iface) {
    close(socket);
}
