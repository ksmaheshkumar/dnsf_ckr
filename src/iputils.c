#include "iputils.h"
#include <arpa/inet.h>

in_addr_t dnsf_ckr_ip2num(const char *dip, size_t dsize) {
    return inet_addr(dip);
}
