#include "sk.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <unistd.h>

dnsf_ckr_sk dnsf_ckr_create_linl1sk(const char *iface) {
    dnsf_ckr_sk sk = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    return sk;
}

void dnsf_ckr_close_linl1sk(const dnsf_ckr_sk socket, const char *iface) {
    close(socket);
}
