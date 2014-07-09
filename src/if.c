#include "if.h"
#include "mem.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "types.h"

#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD

#include <net/if_dl.h>

#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX

#include <ifaddrs.h>
#include <linux/if_packet.h>

#define AF_LINK AF_PACKET

#endif

#include <netinet/in.h>
#include <ifaddrs.h>

char *dnsf_ckr_get_iface_mac(const char *iface) {
    char *retval = NULL;
    unsigned char *mac = NULL;
#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD
    struct ifaddrs *ifap = NULL, *ip;
    int result = getifaddrs(&ifap);
    if (result == 0) {
        for (ip = ifap; ip != NULL; ip = ip->ifa_next) {
            if (strcmp(ip->ifa_name, iface) != 0) continue;
            if (ip->ifa_data != NULL && ip->ifa_addr->sa_family == AF_LINK) {
                retval = (char *) dnsf_ckr_getmem(20);
                mac = (unsigned char *)LLADDR((struct sockaddr_dl *)ip->ifa_addr);
                sprintf(retval, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", *mac, *(mac+1), *(mac+2),
                                                                *(mac+3), *(mac+4), *(mac+5));
            }
        }
        freeifaddrs(ifap);
    }
#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX
    int sockfd;
    struct ifconf ifc;
    struct ifreq ifr, *ifr_i = NULL, *ifr_e = NULL;
    char buf[4096];
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd != -1) {
        if (ioctl(sockfd, SIOCGIFCONF, &ifc) == 0) {
            ifr_i = ifc.ifc_req;
            ifr_e = ifr_i + (ifc.ifc_len / sizeof(ifc));
            for (; ifr_i != ifr_e && retval == NULL; ifr_i++) {
                if (strcmp(ifr_i->ifr_name, iface) != 0) {
                    continue;
                }
                strncpy(ifr.ifr_name, ifr_i->ifr_name, sizeof(ifr.ifr_name) - 1);
                if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == 0) {
                    if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
                        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
                            retval = (char *) dnsf_ckr_getmem(20);
                            mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
                            sprintf(retval, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", *mac, *(mac+1), *(mac+2),
                                                                         *(mac+3), *(mac+4), *(mac+5));

                        }
                    }
                }
            }
        }
        close(sockfd);
    }
#endif
    return retval;
}

char *dnsf_ckr_get_iface_ip(const char *iface) {
    int sfd;
    char *ip = NULL;
    struct ifreq req;
    struct sockaddr *addr;
    sfd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sfd == -1) return NULL;
    strncpy(req.ifr_name, iface, sizeof(req.ifr_name));
    if (ioctl(sfd, SIOCGIFADDR, &req) == -1) {
        close(sfd);
        return NULL;
    }
    ip = (char *) dnsf_ckr_getmem(20);
    addr = &req.ifr_addr;
    if (inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr), ip, 20) == NULL) {
        close(sfd);
        return NULL;
    }
    close(sfd);
    return ip;
}
