#include "iputils.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

in_addr_t dnsf_ckr_ip2num(const char *dip, size_t dsize) {
    return inet_addr(dip);
}

int dnsf_ckr_is_valid_ipv4(const char *addr) {
    const char *a;
    char oct[0xff];
    size_t o = 0;
    memset(oct, 0, sizeof(oct));
    for (a = addr; *a != 0; a++) {
        if (*a == '.' || *(a+1) == 0) {
            if (*(a+1) == 0) {
                oct[o] = *a;
            }
            if (atoi(oct) >= 255 || atoi(oct) < 0) {
                return 0;
            }
            o = 0;
            memset(oct, 0, sizeof(oct));
        } else {
            oct[o] = *a;
            o = (o + 1) % sizeof(oct);
        }
    }
    return 1;
}
