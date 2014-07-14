/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _DNSF_CKR_CONF_H
#define _DNSF_CKR_CONF_H 1

#include <stdio.h>
#include "types.h"

dnsf_ckr_victims_ctx *dnsf_ckr_get_victims_config(FILE *conf);
dnsf_ckr_servers_ctx *dnsf_ckr_get_servers_config(FILE *conf);
dnsf_ckr_hostnames_set_ctx *dnsf_ckr_get_hostnames_config(FILE *conf);
int dnsf_ckr_get_core_int_config(FILE *conf, const char *setting_name, const int default_value);
dnsf_ckr_fakenameserver_ctx *dnsf_ckr_get_fakenameserver_config(FILE *conf, dnsf_ckr_victims_ctx *victims, dnsf_ckr_hostnames_set_ctx *hset);
dnsf_ckr_realdnstransactions_ctx *dnsf_ckr_get_realdnstransactions_config(FILE *conf, dnsf_ckr_victims_ctx *victims, dnsf_ckr_servers_ctx *servers);
int dnsf_ckr_get_mac_of_victims_and_servers(dnsf_ckr_victims_ctx **victims, dnsf_ckr_servers_ctx **servers, const char *loiface);

#endif
