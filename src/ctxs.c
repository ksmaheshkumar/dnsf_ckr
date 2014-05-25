#include "ctxs.h"
#include "mem.h"
#include "iputils.h"
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

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
    p->name = (char *) dnsf_ckr_getmem(nsize + 1);
    memset(p->name, 0, nsize + 1);
    strncpy(p->name, name, nsize);
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
        if (p->hw_addr != NULL) free(p->hw_addr);
        free(p);
    }
}

// dnsf_ckr_servers_ctx stuff

dnsf_ckr_servers_ctx *add_server_to_dnsf_ckr_servers_ctx(dnsf_ckr_servers_ctx *servers, const char *name, const size_t nsize, const char *addr, size_t asize) {
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
    p->name = (char *) dnsf_ckr_getmem(nsize + 1);
    memset(p->name, 0, nsize + 1);
    strncpy(p->name, name, nsize);
    p->addr = dnsf_ckr_ip2num(addr, asize);
    return head;
}

dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_tail(dnsf_ckr_servers_ctx *servers) {
    dnsf_ckr_servers_ctx *p;
    for (p = servers; p->next; p = p->next);
    return p;
}

dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_addr(const char *addr, dnsf_ckr_servers_ctx *servers) {
    dnsf_ckr_servers_ctx *p;
    in_addr_t naddr = inet_addr(addr);
    for (p = servers; p; p = p->next) {
        if (p->addr == naddr) return p;
    }
    return NULL;
}

dnsf_ckr_servers_ctx *get_dnsf_ckr_servers_ctx_name(const char *name, dnsf_ckr_servers_ctx *servers) {
    dnsf_ckr_servers_ctx *p;
    for (p = servers; p; p = p->next) {
        if (strcmp(p->name, name) == 0) return p;
    }
    return 0;
}

void del_dnsf_ckr_servers_ctx(dnsf_ckr_servers_ctx *servers) {
    dnsf_ckr_servers_ctx *t, *p;
    for (t = p = servers; t; p = t) {
        t = p->next;
        if (p->name != NULL) free(p->name);
        if (p->hw_addr != NULL) free(p->hw_addr);
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
    p->name = (char *) dnsf_ckr_getmem(nsize + 1);
    memset(p->name, 0, nsize + 1);
    strncpy(p->name, name, nsize);
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

dnsf_ckr_hostnames_set_ctx *add_set_to_dnsf_ckr_hostnames_set_ctx(dnsf_ckr_hostnames_set_ctx *set, const char *name, size_t nsize) {
    dnsf_ckr_hostnames_set_ctx *head = set, *p;
    if (head != NULL) {
        p = get_dnsf_ckr_hostnames_set_ctx_tail(set);
        new_dnsf_ckr_hostnames_set_ctx(p->next);
        p = p->next;
    } else {
        new_dnsf_ckr_hostnames_set_ctx(head);
        p = head;
    }
    p->name = (char *) dnsf_ckr_getmem(nsize + 1);
    memset(p->name, 0, nsize + 1);
    strncpy(p->name, name, nsize);
    return head;
}

dnsf_ckr_hostnames_set_ctx *get_dnsf_ckr_hostnames_set_ctx_tail(dnsf_ckr_hostnames_set_ctx *set) {
    dnsf_ckr_hostnames_set_ctx *s;
    for (s = set; s->next; s = s->next);
    return s;
}

dnsf_ckr_hostnames_set_ctx *get_dnsf_ckr_hostnames_set_ctx_set(const char *name, dnsf_ckr_hostnames_set_ctx *set) {
    dnsf_ckr_hostnames_set_ctx *s;
    for (s = set; s; s = s->next) {
        if (strcmp(name, s->name) == 0) {
            return s;
        }
    }
    return NULL;
}

void del_dnsf_ckr_hostnames_set_ctx(dnsf_ckr_hostnames_set_ctx *set) {
    dnsf_ckr_hostnames_set_ctx *s, *t;
    for (s = t = set; t; s = t) {
        t = s->next;
        if (s->name != NULL) free(s->name);
        if (s->hostnames != NULL) del_dnsf_ckr_hostnames_ctx(s->hostnames);
        free(s);
    }
}

dnsf_ckr_fakenameserver_ctx *add_faking_to_dnsf_ckr_fakenameserver_ctx(dnsf_ckr_fakenameserver_ctx *nameserver,
                                                                       dnsf_ckr_victims_ctx *victims,
                                                                       dnsf_ckr_hostnames_set_ctx *hset) {
    dnsf_ckr_fakenameserver_ctx *head = nameserver, *p;
    if (head == NULL) {
        new_dnsf_ckr_fakenameserver_ctx(head);
        p = head;
    } else {
        p = get_dnsf_ckr_fakenameserver_ctx_tail(head);
        new_dnsf_ckr_fakenameserver_ctx(p->next);
        p = p->next;
    }
    p->with = victims;
    p->mess_up = hset;
    return head;
}

dnsf_ckr_fakenameserver_ctx *get_dnsf_ckr_fakenameserver_ctx_tail(dnsf_ckr_fakenameserver_ctx *nameserver) {
    dnsf_ckr_fakenameserver_ctx *p;
    for (p = nameserver; p->next; p = p->next);
    return p;
}

void del_dnsf_ckr_fakenameserver_ctx(dnsf_ckr_fakenameserver_ctx *nameserver) {
    dnsf_ckr_fakenameserver_ctx *p, *t;
    for (t = p = nameserver; t; p = t) {
        t = p->next;
        free(p);
    }
}

dnsf_ckr_realdnstransactions_ctx *add_transaction_to_dnsf_ckr_realdnstransactions_ctx(dnsf_ckr_realdnstransactions_ctx *tr, dnsf_ckr_victims_ctx *victim, dnsf_ckr_servers_ctx *send_reqs_to) {
    dnsf_ckr_realdnstransactions_ctx *head = tr, *p;
    if (head == NULL) {
        new_dnsf_ckr_realdnstransactions_ctx(head);
        p = head;
    } else {
        p = get_dnsf_ckr_realdnstransactions_ctx_tail(tr);
        new_dnsf_ckr_realdnstransactions_ctx(p->next);
        p = p->next;
    }
    p->victim = victim;
    p->sends_reqs_to = send_reqs_to;
    return head;
}

dnsf_ckr_realdnstransactions_ctx *get_dnsf_ckr_realdnstransactions_ctx_tail(dnsf_ckr_realdnstransactions_ctx *tr) {
    dnsf_ckr_realdnstransactions_ctx *p;
    for (p = tr; p->next; p = p->next);
    return p;
}

void del_dnsf_ckr_realdnstransactions_ctx(dnsf_ckr_realdnstransactions_ctx *tr) {
    dnsf_ckr_realdnstransactions_ctx *p, *t;
    for (p = t = tr; t; p = t) {
        t = p->next;
        free(p);
    }
}
