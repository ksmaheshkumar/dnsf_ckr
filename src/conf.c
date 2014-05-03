#include "conf.h"
#include "ctxs.h"
#include <stdio.h>

static dnsf_ckr_victims_ctx *dnsf_ckr_get_victims_config(FILE *conf, long cfg_end);

static dnsf_ckr_servers_ctx *dnsf_ckr_get_servers_config(FILE *conf, long cfg_end);

static dnsf_ckr_hostnames_ctx *dnsf_ckr_get_hostnames_config(FILE *conf, long cfg_end);

static int dnsf_ckr_get_dnsproto_int_config(FILE *conf, long cfg_end, int *eof);

static dnsf_ckr_victims_ctx *dnsf_ckr_get_victims_config(FILE *conf, long cfg_end) {
    return NULL;
}

static dnsf_ckr_servers_ctx *dnsf_ckr_get_servers_config(FILE *conf, long cfg_end) {
    return NULL;
}

static dnsf_ckr_hostnames_ctx *dnsf_ckr_get_hostnames_config(FILE *conf, long cfg_end) {
    return NULL;
}

static int dnsf_ckr_get_dnsproto_int_config(FILE *conf, long cfg_end, int *eof) {
    return 0;
}
