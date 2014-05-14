#ifndef _DNSF_CKR_CTXS_H
#define _DNSF_CKR_CTXS_H 1

#include "types.h"


#define new_dnsf_ckr_victims_ctx(v) ( (v) = (dnsf_ckr_victims_ctx *)\
                            dnsf_ckr_getmem(sizeof(dnsf_ckr_victims_ctx)),\
                            (v)->name = NULL,\
                            (v)->name_size = 0,\
                            (v)->next = NULL )

#define new_dnsf_ckr_servers_ctx(s) ( (s) = (dnsf_ckr_servers_ctx *)\
                            dnsf_ckr_getmem(sizeof(dnsf_ckr_servers_ctx)),\
                            (s)->addr = 0,\
                            (s)->next = NULL )

#define new_dnsf_ckr_hostnames_ctx(h) ( (h) = (dnsf_ckr_hostnames_ctx *)\
                            dnsf_ckr_getmem(sizeof(dnsf_ckr_hostnames_ctx)),\
                            (h)->name = NULL,\
                            (h)->name_size = 0,\
                            (h)->next = NULL )

#define new_dnsf_ckr_hostnames_set_ctx(h) ( (h) = (dnsf_ckr_hostnames_set_ctx *)\
                            dnsf_ckr_getmem(sizeof(dnsf_ckr_hostnames_set_ctx)),\
                            (h)->name = NULL,\
                            (h)->name_size = 0,\
                            (h)->hostnames = NULL,\
                            (h)->next = NULL )

#define new_dnsf_ckr_fakenameserver_ctx(f) ( (f) = (dnsf_ckr_fakenameserver_ctx *)\
                            dnsf_ckr_getmem(sizeof(dnsf_ckr_fakenameserver_ctx)),\
                            (f)->with = NULL,\
                            (f)->mess_up = NULL,\
                            (f)->next = NULL )

// dnsf_ckr_victims_ctx stuff

dnsf_ckr_victims_ctx *add_victim_to_dnsf_ckr_victims_ctx(dnsf_ckr_victims_ctx *victims, const char *name, size_t nsize,
                                                         const char *addr, size_t asize);
dnsf_ckr_victims_ctx *get_dnsf_ckr_victims_ctx_tail(dnsf_ckr_victims_ctx *victims);
dnsf_ckr_victims_ctx *get_dnsf_ckr_victims_ctx_victim(const char *victim, dnsf_ckr_victims_ctx *victims);
void del_dnsf_ckr_victims_ctx(dnsf_ckr_victims_ctx *victims);

// dnsf_ckr_servers_ctx stuff

dnsf_ckr_servers_ctx *add_server_to_dnsf_ckr_servers_ctx(dnsf_ckr_servers_ctx *servers,
                                                         const char *addr, size_t asize);
dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_tail(dnsf_ckr_servers_ctx *servers);
dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_addr(const char *addr, dnsf_ckr_servers_ctx *servers);
void del_dnsf_ckr_servers_ctx(dnsf_ckr_servers_ctx *servers);

// dnsf_ckr_hostnames_ctx stuff

dnsf_ckr_hostnames_ctx *add_host_to_dnsf_ckr_hostnames_ctx(dnsf_ckr_hostnames_ctx *hostnames, const char *name,
                                                           size_t nsize, const char *addr, size_t asize);
dnsf_ckr_hostnames_ctx *get_dnsf_ckr_hostnames_ctx_tail(dnsf_ckr_hostnames_ctx *hostnames);
dnsf_ckr_hostnames_ctx *get_dnsf_ckr_hostnames_ctx_name(const char *name, dnsf_ckr_hostnames_ctx *hostnames);
void del_dnsf_ckr_hostnames_ctx(dnsf_ckr_hostnames_ctx *hostnames);

// dnsf_ckr_hostnames_set_ctx stuff

dnsf_ckr_hostnames_set_ctx *add_set_to_dnsf_ckr_hostnames_set_ctx(dnsf_ckr_hostnames_set_ctx *set, const char *name, size_t nsize);
dnsf_ckr_hostnames_set_ctx *get_dnsf_ckr_hostnames_set_ctx_tail(dnsf_ckr_hostnames_set_ctx *set);
dnsf_ckr_hostnames_set_ctx *get_dnsf_ckr_hostnames_set_ctx_set(const char *name, dnsf_ckr_hostnames_set_ctx *set);
void del_dnsf_ckr_hostnames_set_ctx(dnsf_ckr_hostnames_set_ctx *set);

// dnsf_ckr_fakenameserver_ctx stuff

dnsf_ckr_fakenameserver_ctx *add_faking_to_dnsf_ckr_fakenameserver_ctx(dnsf_ckr_fakenameserver_ctx *nameserver,
                                                                       dnsf_ckr_victims_ctx *victims,
                                                                       dnsf_ckr_hostnames_set_ctx *hset);

dnsf_ckr_fakenameserver_ctx *get_dnsf_ckr_fakenameserver_ctx_tail(dnsf_ckr_fakenameserver_ctx *nameserver);

void del_dnsf_ckr_fakenameserver_ctx(dnsf_ckr_fakenameserver_ctx *nameserver);

#endif
