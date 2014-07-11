/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _DNSF_CKR_IPUTILS_H
#define _DNSF_CKR_IPUTILS_H 1

#include <sys/types.h>

#include "types.h"

#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX

#include <netinet/in.h>

#endif

in_addr_t dnsf_ckr_ip2num(const char *dip, size_t dsize);
int dnsf_ckr_is_valid_ipv4(const char *addr);

#endif
