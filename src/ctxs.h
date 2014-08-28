/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _DNSF_CKR_CTXS_H
#define _DNSF_CKR_CTXS_H 1

#include "types.h"


#define new_dnsf_ckr_victims_ctx(v) ( (v) = (dnsf_ckr_victims_ctx *)\
                            dnsf_ckr_getmemory(sizeof(dnsf_ckr_victims_ctx)),\
                            (v)->name = NULL,\
                            (v)->name_size = 0,\
                            (v)->hw_addr = NULL,\
                            (v)->next = NULL )

#define new_dnsf_ckr_servers_ctx(s) ( (s) = (dnsf_ckr_servers_ctx *)\
                            dnsf_ckr_getmemory(sizeof(dnsf_ckr_servers_ctx)),\
                            (s)->name = NULL,\
                            (s)->name_size = 0,\
                            (s)->addr = 0,\
                            (s)->hw_addr = NULL,\
                            (s)->next = NULL )

#define new_dnsf_ckr_hostnames_ctx(h) ( (h) = (dnsf_ckr_hostnames_ctx *)\
                            dnsf_ckr_getmemory(sizeof(dnsf_ckr_hostnames_ctx)),\
                            (h)->name = NULL,\
                            (h)->name_size = 0,\
                            (h)->next = NULL )

#define new_dnsf_ckr_hostnames_set_ctx(h) ( (h) = (dnsf_ckr_hostnames_set_ctx *)\
                            dnsf_ckr_getmemory(sizeof(dnsf_ckr_hostnames_set_ctx)),\
                            (h)->name = NULL,\
                            (h)->name_size = 0,\
                            (h)->hostnames = NULL,\
                            (h)->next = NULL )

#define new_dnsf_ckr_fakenameserver_ctx(f) ( (f) = (dnsf_ckr_fakenameserver_ctx *)\
                            dnsf_ckr_getmemory(sizeof(dnsf_ckr_fakenameserver_ctx)),\
                            (f)->with = NULL,\
                            (f)->mess_up = NULL,\
                            (f)->next = NULL )

#define new_dnsf_ckr_realdnstransactions_ctx(r) ((r) = (dnsf_ckr_realdnstransactions_ctx *)\
                            dnsf_ckr_getmemory(sizeof(dnsf_ckr_realdnstransactions_ctx)),\
                            (r)->victim = NULL,\
                            (r)->sends_reqs_to = NULL,\
                            (r)->next = NULL )

#define new_dnsf_ckr_dnsresolvcache_ctx(d) ( (d) = (dnsf_ckr_dnsresolvcache_ctx *)\
                            dnsf_ckr_getmemory(sizeof(dnsf_ckr_dnsresolvcache_ctx)),\
                            (d)->dname = NULL,\
                            (d)->dname_size = 0,\
                            (d)->reply = NULL,\
                            (d)->reply_size = 0 )

// dnsf_ckr_victims_ctx stuff

dnsf_ckr_victims_ctx *add_victim_to_dnsf_ckr_victims_ctx(dnsf_ckr_victims_ctx *victims, const char *name, size_t nsize,
                                                         const char *addr, size_t asize);
dnsf_ckr_victims_ctx *get_dnsf_ckr_victims_ctx_tail(dnsf_ckr_victims_ctx *victims);
dnsf_ckr_victims_ctx *get_dnsf_ckr_victims_ctx_victim(const char *victim, dnsf_ckr_victims_ctx *victims);
void del_dnsf_ckr_victims_ctx(dnsf_ckr_victims_ctx *victims);

// dnsf_ckr_servers_ctx stuff

dnsf_ckr_servers_ctx *add_server_to_dnsf_ckr_servers_ctx(dnsf_ckr_servers_ctx *servers,
                                                         const char *name, size_t nsize,
                                                         const char *addr, size_t asize);
dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_tail(dnsf_ckr_servers_ctx *servers);
dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_addr(const char *addr, dnsf_ckr_servers_ctx *servers);
dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_name(const char *name, dnsf_ckr_servers_ctx *servers);
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

// dnsf_ckr_realdnstransactions_ctx stuff

dnsf_ckr_realdnstransactions_ctx *add_transaction_to_dnsf_ckr_realdnstransactions_ctx(dnsf_ckr_realdnstransactions_ctx *tr, dnsf_ckr_victims_ctx *victim, dnsf_ckr_servers_ctx *send_reqs_to);
dnsf_ckr_realdnstransactions_ctx *get_dnsf_ckr_realdnstransactions_ctx_tail(dnsf_ckr_realdnstransactions_ctx *tr);
void del_dnsf_ckr_realdnstransactions_ctx(dnsf_ckr_realdnstransactions_ctx *tr);

// dnsf_ckr_dnsresolvcache_ctx stuff

dnsf_ckr_dnsresolvcache_ctx *push_resolution_to_dnsf_ckr_dnsresolvcache_ctx(dnsf_ckr_dnsresolvcache_ctx **resolv, size_t max_cache_size, const char *dname, const size_t dname_size, const unsigned char *reply, const size_t reply_size);
dnsf_ckr_dnsresolvcache_ctx *pop_back_resolution_from_dnsf_ckr_dnsresolvcache_ctx(dnsf_ckr_dnsresolvcache_ctx **resolv);
dnsf_ckr_dnsresolvcache_ctx *get_dnsf_ckr_dnsresolvcache_ctx_dname(const char *dname, dnsf_ckr_dnsresolvcache_ctx *resolv);
size_t count_of_dnsf_ckr_dnsresolvcache_ctx(dnsf_ckr_dnsresolvcache_ctx *resolv);
void del_dnsf_ckr_dnsresolvcache_ctx(dnsf_ckr_dnsresolvcache_ctx *resolv);

#endif
