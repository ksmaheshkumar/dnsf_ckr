/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _DNSF_CKR_LAYER1SK_H
#define _DNSF_CKR_LAYER1SK_H 1

#include "types.h"

#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD

#include "freebsd/sk.h"

#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX

#include "linux/sk.h"

#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_WINDOWS

// Whatever!

#endif

dnsf_ckr_sk dnsf_ckr_create_layer1_socket(const char *iface);

void dnsf_ckr_close_layer1_socket(const dnsf_ckr_sk socket, const char *iface);

#endif
