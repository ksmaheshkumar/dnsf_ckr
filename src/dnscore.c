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

unsigned char *pack_dns_data(dnspktctx dnspkt) {
    return NULL;
}
