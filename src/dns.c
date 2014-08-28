/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "dns.h"
#include "mem.h"
#include "types.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#define new_dnsf_ckr_dns_header(p) { p = (struct dnsf_ckr_dns_header *) dnsf_ckr_getmemory(sizeof(struct dnsf_ckr_dns_header));\
                                    if (p == NULL) exit(1);\
                                    p->rscrecfmt.rdata = NULL; }

#define sf_i(i, s) ( (i) % (s) )

#define getbit(w, b) ( ((unsigned long) w << b) >> 31 )

struct dnsf_ckr_dns_header *unpack_dns_data(const unsigned char *raw_buf, const size_t bufsz) {
    size_t b;
    struct dnsf_ckr_dns_header *pkt = NULL;
    size_t c_off;
    if (raw_buf == NULL || bufsz < 11) return NULL;
    new_dnsf_ckr_dns_header(pkt);
    pkt->id = (((unsigned short)raw_buf[0]) << 8) | raw_buf[1];
    pkt->qr = (raw_buf[2] >> 7);
    pkt->opcode = ((raw_buf[2] & 0x78) >> 3);
    pkt->aa = ((raw_buf[2] & 0x04) >> 2);
    pkt->tc = ((raw_buf[2] & 0x02) >> 1);
    pkt->rd = (raw_buf[2] & 0x1);
    pkt->ra = (raw_buf[3] >> 7);
    pkt->z = ((raw_buf[3] & 0x70) >> 4);
    pkt->rcode = (raw_buf[3] & 0x0f);
    pkt->qdcount = (((unsigned short)raw_buf[4]) << 8) | raw_buf[ 5];
    pkt->ancount = (((unsigned short)raw_buf[6]) << 8) | raw_buf[ 7];
    pkt->nscount = (((unsigned short)raw_buf[8]) << 8) | raw_buf[ 9];
    pkt->arcount = (((unsigned short)raw_buf[10]) << 8) | raw_buf[11];
    if (pkt->qdcount > 0) { // se a question veio de marte e tiver mais de uma,
                            // pega a primeira e que se ... o resto do contato
                            // que tentaram fazer.
        memset(pkt->questionsec.qname, 0, sizeof(pkt->questionsec.qname));
        for (b = 12; b < bufsz && raw_buf[sf_i(b, bufsz)] != 0; b++) {
            pkt->questionsec.qname[b - 12] = raw_buf[sf_i(b, bufsz)];
        }
        c_off = b + 1;
        pkt->questionsec.qtype = (((unsigned short)raw_buf[sf_i(c_off, bufsz)]) << 8) |
                                 ((unsigned short)raw_buf[sf_i(c_off + 1, bufsz)]);
        pkt->questionsec.qclass = (((unsigned short)raw_buf[sf_i(c_off + 2, bufsz)]) << 8) |
                                  ((unsigned short)raw_buf[sf_i(c_off + 3, bufsz)]);
    }
    return pkt;
}

size_t pack_dns_data(unsigned char **output, struct dnsf_ckr_dns_header pkt) {
    unsigned char *pdata = *output;
    unsigned char *p, *d;
    *output = (unsigned char *) malloc(11 + pkt.qdcount +
                                     pkt.ancount + pkt.nscount +
                                     pkt.arcount + 255);
    pdata = *output;
    p = pdata;
    *p = (pkt.id >> 8);
    p++;
    *p = (pkt.id & 0x00ff);
    p++;
    *p = ((unsigned char)pkt.qr << 7) |
         ((unsigned char)pkt.opcode << 3) |
         ((unsigned char)pkt.aa << 2) |
         ((unsigned char)pkt.tc << 1) |
         ((unsigned char)pkt.rd);
    p++;
    *p = ((unsigned char)pkt.ra << 7) |
         ((unsigned char)pkt.z << 4) |
         ((unsigned char)pkt.rcode);
    p++;
    *p = (pkt.qdcount >> 8);
    p++;
    *p = (pkt.qdcount & 0x00ff);
    p++;
    *p = (pkt.ancount >> 8);
    p++;
    *p = (pkt.ancount & 0x00ff);
    p++;
    *p = (pkt.nscount >> 8);
    p++;
    *p = (pkt.nscount & 0x00ff);
    p++;
    *p = (pkt.arcount >> 8);
    p++;
    *p = (pkt.arcount & 0x00ff);
    p++;
    if (pkt.qdcount > 0) {
        //*p = strlen((char *)pkt.questionsec.qname);
        //p++;
        //memcpy(p, pkt.questionsec.qname, (size_t)*(p-1));
        //p += *(p-1);
        for (d = &pkt.questionsec.qname[0]; *d != 0; d++, p++) {
            *p = *d;
        }
        *p = 0;
        p++;
        *p = (pkt.questionsec.qtype >> 8);
        p++;
        *p = (pkt.questionsec.qtype & 0x00ff);
        p++;
        *p = (pkt.questionsec.qclass >> 8);
        p++;
        *p = (pkt.questionsec.qclass & 0x00ff);
        p++;
    }
    if (pkt.ancount > 0) {
        for (d = &pkt.questionsec.qname[0]; *d != 0; d++, p++) {
            *p = *d;
        }
        //*p = 0xc0;
        //p++;
        //*p = 0x0c;
        *p = 0;
        p++;
        *p = (pkt.rscrecfmt.type >> 8);
        p++;
        *p = (pkt.rscrecfmt.type & 0x00ff);
        p++;
        *p = (pkt.rscrecfmt.clss >> 8);
        p++;
        *p = (pkt.rscrecfmt.clss & 0x00ff);
        p++;
        *p = (pkt.rscrecfmt.ttl >> 24);
        p++;
        *p = ((pkt.rscrecfmt.ttl & 0x00ff0000) >> 16);
        p++;
        *p = ((pkt.rscrecfmt.ttl & 0x0000ff00) >>  8);
        p++;
        *p = (pkt.rscrecfmt.ttl & 0x000000ff);
        p++;
        *p = (pkt.rscrecfmt.rdlen >> 8);
        p++;
        *p = (pkt.rscrecfmt.rdlen & 0x00ff);
        p++;
        if (pkt.rscrecfmt.rdata != NULL) {
            memcpy(p, pkt.rscrecfmt.rdata, pkt.rscrecfmt.rdlen);
            p += pkt.rscrecfmt.rdlen;
        }
    }

    return (p - pdata);
}

unsigned char *dnsf_ckr_mk_dnsresponse(size_t *bufsz, const unsigned char *query, const size_t query_size, unsigned int dnsserver_addr) {
    unsigned char buf[0xffff];
    unsigned char *retval = NULL;
    int bufsize = 0;
    dnsf_ckr_sk conn;
    struct timeval tv;
    struct sockaddr_in conn_in;
    //socklen_t conn_in_sz = sizeof(conn_in);
    if (bufsz == NULL) {
        return NULL;
    }
    *bufsz = 0;
    conn = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = 5;
    setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    conn_in.sin_family = AF_INET;
    conn_in.sin_port = htons(53);
    conn_in.sin_addr.s_addr = htonl(dnsserver_addr);
    //bufsize = sendto(conn, query, query_size, 0, (struct sockaddr *)&conn_in, sizeof(conn_in));
    bufsize = sendto(conn, query, query_size, 0, (struct sockaddr *)&conn_in, sizeof(conn_in));
    if ((size_t)bufsize == query_size) {
        //printf("SENT!\n");
        bufsize = -1;
        bufsize = recvfrom(conn, buf, sizeof(buf), 0, NULL, NULL);
        perror("recvfrom");
        printf("RECV = %d\n", bufsize);
        if (bufsize > 0) {
            retval = (unsigned char *) dnsf_ckr_getmemory(bufsize);
            memcpy(retval, buf, bufsize);
            *bufsz = bufsize;
        }
    }
    close(conn);
    return retval;
}
