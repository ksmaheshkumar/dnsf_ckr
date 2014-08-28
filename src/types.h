/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _DNSF_CKR_TYPES_H
#define _DNSF_CKR_TYPES_H 1

#include <stdlib.h>

#define DNSF_CKR_VERSION        "0.0.1.0"

#define DNSF_CKR_PLATFORM_FREEBSD       1
#define DNSF_CKR_PLATFORM_LINUX         2
#define DNSF_CKR_PLATFORM_WINDOWS       3

#define DNSF_CKR_TGT_OS         DNSF_CKR_PLATFORM_LINUX

#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX

#include <netinet/in.h>

#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD

#include <sys/types.h>

#endif

#define DNSF_CKR_REQ_HANDLERS_NR 50

typedef struct _dnsf_ckr_victims_ctx {
    char *name;
    size_t name_size;
    in_addr_t addr;
    char *hw_addr;
    struct _dnsf_ckr_victims_ctx *next;
}dnsf_ckr_victims_ctx;

typedef struct _dnsf_ckr_servers_ctx {
    char *name;
    size_t name_size;
    in_addr_t addr;
    char *hw_addr;
    struct _dnsf_ckr_servers_ctx *next;
}dnsf_ckr_servers_ctx;

typedef struct _dnsf_ckr_hostnames_ctx {
    char *name;
    size_t name_size;
    in_addr_t addr;
    struct _dnsf_ckr_hostnames_ctx *next;
}dnsf_ckr_hostnames_ctx;

typedef struct _dnsf_ckr_hostnames_set_ctx {
    char *name;
    size_t name_size;
    dnsf_ckr_hostnames_ctx *hostnames;
    struct _dnsf_ckr_hostnames_set_ctx *next;
}dnsf_ckr_hostnames_set_ctx;

typedef struct _dnsf_ckr_fakenameserver_ctx {
    dnsf_ckr_victims_ctx *with;
    dnsf_ckr_hostnames_set_ctx *mess_up;
    struct _dnsf_ckr_fakenameserver_ctx *next;
}dnsf_ckr_fakenameserver_ctx;

typedef struct _dnsf_ckr_realdnstransactions_ctx {
    dnsf_ckr_victims_ctx *victim;
    dnsf_ckr_servers_ctx *sends_reqs_to;
    struct _dnsf_ckr_realdnstransactions_ctx *next;
}dnsf_ckr_realdnstransactions_ctx;

typedef struct _dnsf_ckr_dnsproto {
    int ttl_in_secs;
    dnsf_ckr_victims_ctx *victims;
    dnsf_ckr_servers_ctx *servers;
    dnsf_ckr_hostnames_ctx *hostnames;
}dnsf_ckr_dnsproto;

typedef struct _dnsf_ckr_dnsresolvcache_ctx {
    char *dname;
    size_t dname_size;
    unsigned char *reply;
    size_t reply_size;
    struct _dnsf_ckr_dnsresolvcache_ctx *next;
}dnsf_ckr_dnsresolvcache_ctx;

#if DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_FREEBSD || DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_LINUX

#include <pthread.h>

typedef int dnsf_ckr_sk;

typedef pthread_t dnsf_ckr_thread;

#elif DNSF_CKR_TGT_OS == DNSF_CKR_PLATFORM_WINDOWS

#include <windows.h>

typedef HANDLE dnsf_ckr_sk;

#endif

#endif
