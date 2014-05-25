#ifndef _DNSF_CKR_TYPES_H
#define _DNSF_CKR_TYPES_H 1

#include <stdlib.h>
#include <sys/types.h>

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

typedef int dnsf_ckr_sk;

#endif
