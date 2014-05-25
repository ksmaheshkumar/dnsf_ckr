#ifndef _DNSF_CKR_CONF_H
#define _DNSF_CKR_CONF_H 1

#include <stdio.h>
#include "types.h"

dnsf_ckr_victims_ctx *dnsf_ckr_get_victims_config(FILE *conf);
dnsf_ckr_servers_ctx *dnsf_ckr_get_servers_config(FILE *conf);
dnsf_ckr_hostnames_set_ctx *dnsf_ckr_get_hostnames_config(FILE *conf);
int dnsf_ckr_get_dnsproto_int_config(FILE *conf, const char *setting_name, const int default_value);
dnsf_ckr_fakenameserver_ctx *dnsf_ckr_get_fakenameserver_config(FILE *conf, dnsf_ckr_victims_ctx *victims, dnsf_ckr_hostnames_set_ctx *hset);
dnsf_ckr_realdnstransactions_ctx *dnsf_ckr_get_realdnstransactions_config(FILE *conf, dnsf_ckr_victims_ctx *victims, dnsf_ckr_servers_ctx *servers);

#endif
