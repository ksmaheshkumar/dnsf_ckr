#include "ctxs.h"
#include "mem.h"
#include "iputils.h"
#include <string.h>

dnsf_ckr_victims_ctx *add_victim_to_dnsf_ckr_victims_ctx(dnsf_ckr_victims_ctx *victims, const char *name, size_t nsize,
                                                         const char *addr, size_t asize) {
    dnsf_ckr_victims_ctx *head = victims, *p;
    if (head == NULL) {
        new_dnsf_ckr_victims_ctx(head);
        p = head;
    } else {
        p = get_dnsf_ckr_victims_ctx_tail(victims);
        new_dnsf_ckr_victims_ctx(p->next);
        p = p->next;
    }
    p->name_size = nsize;
    p->name = (char *) dnsf_ckr_getmem(nsize);
    memset(p->name, 0, nsize);
    strncpy(p->name, name, nsize - 1);
    p->addr = dnsf_ckr_ip2num(addr, asize);
    return head;
}

dnsf_ckr_victims_ctx *get_dnsf_ckr_victims_ctx_tail(dnsf_ckr_victims_ctx *victims) {
    dnsf_ckr_victims_ctx *p;
    for (p = victims; p->next; p = p->next);
    return p;
}

dnsf_ckr_victims_ctx *get_dnsf_ckr_victims_ctx_victim(const char *victim, dnsf_ckr_victims_ctx *victims) {
    dnsf_ckr_victims_ctx *p;
    for (p = victims; p; p = p->next) {
        if (strcmp(p->name, victim) == 0) return p;
    }
    return NULL;
}

void del_dnsf_ckr_victims_ctx(dnsf_ckr_victims_ctx *victims) {
    dnsf_ckr_victims_ctx *p, *t;
    for (p = t = victims; t; p = t) {
        t = p->next;
        if (p->name != NULL) free(p->name);
        free(p);
    }
}

// dnsf_ckr_servers_ctx stuff

dnsf_ckr_servers_ctx *add_server_to_dnsf_ckr_servers_ctx(dnsf_ckr_servers_ctx *servers, const char *name, size_t nsize,
                                                         const char *addr, size_t asize) {
    dnsf_ckr_servers_ctx *head = servers, *p;
    if (head == NULL) {
        new_dnsf_ckr_servers_ctx(head);
        p = head;
    } else {
        p = get_dnsf_ckr_servers_ctx_tail(servers);
        new_dnsf_ckr_servers_ctx(p->next);
        p = p->next;
    }
    p->name_size = nsize;
    p->name = (char *) dnsf_ckr_getmem(nsize);
    memset(p->name, 0, nsize);
    strncpy(p->name, name, nsize-1);
    p->addr = dnsf_ckr_ip2num(addr, asize);
    return head;
}

dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_tail(dnsf_ckr_servers_ctx *servers) {
    dnsf_ckr_servers_ctx *p;
    for (p = servers; p->next; p = p->next);
    return p;
}

dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_name(const char *name, dnsf_ckr_servers_ctx *servers) {
    dnsf_ckr_servers_ctx *p;
    for (p = servers; p; p = p->next) {
        if (strcmp(name, p->name) == 0) return p;
    }
    return NULL;
}

void del_dnsf_ckr_servers_ctx(dnsf_ckr_servers_ctx *servers) {
    dnsf_ckr_servers_ctx *t, *p;
    for (t = p = servers; t; p = t) {
        t = p->next;
        if (p->name != NULL) free(p->name);
        free(p);
    }
}

// dnsf_ckr_hostnames_ctx stuff

dnsf_ckr_hostnames_ctx *add_host_to_dnsf_ckr_hostnames_ctx(dnsf_ckr_hostnames_ctx *hostnames, const char *name,
                                                           size_t nsize, const char *addr, size_t asize) {
    dnsf_ckr_hostnames_ctx *head = hostnames, *p;
    if (head == NULL) {
        new_dnsf_ckr_hostnames_ctx(head);
        p = head;
    } else {
        p = get_dnsf_ckr_hostnames_ctx_tail(hostnames);
        new_dnsf_ckr_hostnames_ctx(p->next);
        p = p->next;
    }
    p->name_size = nsize;
    p->name = (char *) dnsf_ckr_getmem(nsize);
    memset(p->name, 0, nsize);
    strncpy(p->name, name, nsize - 1);
    p->addr = dnsf_ckr_ip2num(addr, asize);
    return head;
}

dnsf_ckr_hostnames_ctx *get_dnsf_ckr_hostnames_ctx_tail(dnsf_ckr_hostnames_ctx *hostnames) {
    dnsf_ckr_hostnames_ctx *p;
    for (p = hostnames; p->next; p = p->next);
    return p;
}

dnsf_ckr_hostnames_ctx *get_dnsf_ckr_hostnames_ctx_name(const char *name, dnsf_ckr_hostnames_ctx *hostnames) {
    dnsf_ckr_hostnames_ctx *p;
    for (p = hostnames; p; p = p->next) {
        if (strcmp(p->name, name) == 0) return p;
    }
    return NULL;
}

void del_dnsf_ckr_hostnames_ctx(dnsf_ckr_hostnames_ctx *hostnames) {
    dnsf_ckr_hostnames_ctx *p, *t;
    for (p = t = hostnames; t; p = t) {
        t = p->next;
        if (p->name != NULL) free(p->name);
        free(p);
    }
}

