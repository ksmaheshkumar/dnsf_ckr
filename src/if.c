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
#include <net/if_dl.h>
#include <netinet/in.h>
#include <ifaddrs.h>

char *dnsf_ckr_get_iface_mac(const char *iface) {
    struct ifaddrs *ifap = NULL, *ip;
    unsigned char *mac;
    char *retval = NULL;
    int result = getifaddrs(&ifap);
    if (result == 0) {
        for (ip = ifap; ip != NULL; ip = ip->ifa_next) {
            if (strcmp(ip->ifa_name, iface) != 0) continue;
            if (ip->ifa_data != NULL && ip->ifa_addr->sa_family == AF_LINK) {
                mac = (unsigned char *)LLADDR((struct sockaddr_dl *)ip->ifa_addr);
                retval = (char *) dnsf_ckr_getmem(20);
                sprintf(retval, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", *mac, *(mac+1), *(mac+2),
                                                                *(mac+3), *(mac+4), *(mac+5));
            }
        }
        freeifaddrs(ifap);
    }
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
