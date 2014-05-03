#include "dnscore.h"
#include <string.h>

#define new_dnspktctx(p) { p = (dnspktctx *) malloc(sizeof(dnspktctx));\
                           if (p == NULL) exit(1); }

#define sf_i(i, s) ( (i) % (s) )

dnspktctx *unpack_dns_data(const unsigned char *raw_buf, size_t bufsz) {
    dnspktctx *pkt = NULL;
    size_t c_off;
    if (raw_buf == NULL || bufsz < 11) return NULL;
    new_dnspktctx(pkt);
    pkt->id = (((unsigned short)raw_buf[0]) << 8) | raw_buf[1];
    pkt->qr = (raw_buf[2] & 0x80) >> 7;
    pkt->opcode = (raw_buf[2] & 0x74) >> 4;
    pkt->aatcrdra = ((raw_buf[2] & 0x03) << 1) | ((raw_buf[3] & 0x80) >> 7);
    pkt->z = (raw_buf[3] & 0x70) >> 4; //duh!
    pkt->rcode = (raw_buf[3] & 0x0f);
    pkt->qdcount = (((unsigned short)raw_buf[4]) << 8) | raw_buf[ 5];
    pkt->ancount = (((unsigned short)raw_buf[6]) << 8) | raw_buf[ 7];
    pkt->nscount = (((unsigned short)raw_buf[8]) << 8) | raw_buf[ 9];
    pkt->arcount = (((unsigned short)raw_buf[9]) << 8) | raw_buf[10];
    if (pkt->qdcount > 0) { // se a question veio de marte e tiver mais de uma,
                            // pega a primeira e que se foda o resto do contato
                            // que tentaram fazer.
        memset(pkt->questionsec.qname, 0, sizeof(pkt->questionsec.qname));
        memcpy(pkt->questionsec.qname, &raw_buf[sf_i(12, bufsz)],
               (size_t)raw_buf[sf_i(11, bufsz)]);
        c_off = raw_buf[sf_i(11, bufsz)];// + 1;
        pkt->questionsec.qtype = (((unsigned short)raw_buf[sf_i(12 + c_off, bufsz)]) << 8) |
                                 raw_buf[sf_i(13 + c_off, bufsz)];
        pkt->questionsec.qclass = (((unsigned short)raw_buf[sf_i(14 + c_off, bufsz)]) << 8) |
                                  raw_buf[sf_i(15 + c_off, bufsz)];
    } else { // da mesma forma pega so o primeiro.
        memset(pkt->rscrecfmt.name, 0, sizeof(pkt->rscrecfmt.name));
        memcpy(pkt->rscrecfmt.name, &raw_buf[sf_i(12, bufsz)], (size_t)raw_buf[sf_i(11, bufsz)]);
        c_off = raw_buf[sf_i(11, bufsz)];// + 1;
        pkt->rscrecfmt.type = (((unsigned short)raw_buf[sf_i(12 + c_off, bufsz)]) << 8) |
                              raw_buf[sf_i(13 + c_off, bufsz)];
        pkt->rscrecfmt.clss = (((unsigned short)raw_buf[sf_i(14 + c_off, bufsz)]) << 8) |
                              raw_buf[sf_i(15 + c_off, bufsz)];
        pkt->rscrecfmt.ttl = (((unsigned long)raw_buf[sf_i(16 + c_off, bufsz)]) << 24) |
                             (((unsigned long)raw_buf[sf_i(17 + c_off, bufsz)]) << 16) |
                             (((unsigned long)raw_buf[sf_i(18 + c_off, bufsz)]) <<  8) |
                             raw_buf[sf_i(19 + c_off, bufsz)];
        pkt->rscrecfmt.rdlen = (((unsigned short)raw_buf[sf_i(20 + c_off, bufsz)]) << 8) |
                               raw_buf[sf_i(21 + c_off, bufsz)];
        if (pkt->rscrecfmt.rdlen > 0) {
            pkt->rscrecfmt.rdata = (unsigned char *) malloc(pkt->rscrecfmt.rdlen + 1);
            memset(pkt->rscrecfmt.rdata, 0, pkt->rscrecfmt.rdlen + 1);
            memcpy(pkt->rscrecfmt.rdata, &raw_buf[sf_i(22 + c_off, bufsz)], pkt->rscrecfmt.rdlen);
        } else {
            pkt->rscrecfmt.rdata = NULL;
        }
    }
    return pkt;
}

size_t pack_dns_data(unsigned char **output, dnspktctx pkt) {
    unsigned char *pdata = *output;
    unsigned char *p;
    pdata = (unsigned char *) malloc(11 + pkt.qdcount +
                                     pkt.ancount + pkt.nscount +
                                     pkt.arcount + 255);
    p = pdata;
    *p = ((pkt.id & 0xff00) >> 8);
    p++;
    *p = (pkt.id & 0x00ff);
    p++;
    *p = pkt.qr;
    *p = (*p << 7);
    *p = (*p | pkt.opcode);
    *p |= ((pkt.aatcrdra & 0x0e) >> 1);
    p++;
    *p = (pkt.aatcrdra & 0x1) << 7;
    *p |= pkt.rcode;
    p++;
    *p = ((pkt.qdcount & 0xff000000) >> 24);
    p++;
    *p = ((pkt.qdcount & 0x00ff0000) >> 16);
    p++;
    *p = ((pkt.qdcount & 0x0000ff00) >>  8);
    p++;
    *p = (pkt.qdcount & 0x000000ff);
    p++;
    *p = ((pkt.ancount & 0xff000000) >> 24);
    p++;
    *p = ((pkt.ancount & 0x00ff0000) >> 16);
    p++;
    *p = ((pkt.ancount & 0x0000ff00) >>  8);
    p++;
    *p = (pkt.ancount & 0x000000ff);
    p++;
    *p = ((pkt.nscount & 0xff000000) >> 24);
    p++;
    *p = ((pkt.nscount & 0x00ff0000) >> 16);
    p++;
    *p = ((pkt.nscount & 0x0000ff00) >>  8);
    p++;
    *p = (pkt.nscount & 0x000000ff);
    p++;
    *p = ((pkt.arcount & 0xff000000) >> 24);
    p++;
    *p = ((pkt.arcount & 0x00ff0000) >> 16);
    p++;
    *p = ((pkt.arcount & 0x0000ff00) >>  8);
    p++;
    *p = (pkt.arcount & 0x000000ff);
    p++;
    if (pkt.qdcount > 0) {
        *p = strlen((char *)pkt.questionsec.qname);
        p++;
        memcpy(p, pkt.questionsec.qname, (size_t)*(p-1));
        p += *(p-1);
        *p = ((pkt.questionsec.qtype & 0xff00) >> 8);
        p++;
        *p = (pkt.questionsec.qtype & 0x00ff);
        p++;
        *p = ((pkt.questionsec.qclass & 0xff00) >> 8);
        p++;
        *p = (pkt.questionsec.qclass & 0x00ff);
        p++;
    } else {
        *p = strlen((char *)pkt.rscrecfmt.name);
        p++;
        memset(p, 0, 255);
        memcpy(p, pkt.rscrecfmt.name, (size_t)*(p-1));
        p++;
        *p += ((pkt.rscrecfmt.type & 0xff00) >> 8);
        p++;
        *p = (pkt.rscrecfmt.type & 0x00ff);
        p++;
        *p = ((pkt.rscrecfmt.clss & 0xff00) >> 8);
        p++;
        *p = (pkt.rscrecfmt.clss & 0x00ff);
        p++;
        *p = ((pkt.rscrecfmt.ttl & 0xff000000) >> 24);
        p++;
        *p = ((pkt.rscrecfmt.ttl & 0x00ff0000) >> 16);
        p++;
        *p = ((pkt.rscrecfmt.ttl & 0x0000ff00) >>  8);
        p++;
        *p = (pkt.rscrecfmt.ttl & 0x000000ff);
        p++;
        *p = ((pkt.rscrecfmt.rdlen & 0xff00) >> 8);
        p++;
        *p = (pkt.rscrecfmt.rdlen & 0x00ff);
        p++;
        memcpy(p, pkt.rscrecfmt.rdata, pkt.rscrecfmt.rdlen);
        p++;
    }

    return (p - pdata);
}
