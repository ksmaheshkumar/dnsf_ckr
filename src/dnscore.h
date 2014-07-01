#ifndef _DNSF_CKR_DNSCORE_H
#define _DNSF_CKR_DNSCORE_H

#include <stdlib.h>

#define DNSF_CKR_TYPE_A         0x1
#define DNSF_CKR_TYPE_NS        0x2
#define DNSF_CKR_TYPE_MD        0x3
#define DNSF_CKR_TYPE_MF        0x4
#define DNSF_CKR_TYPE_CNAME     0x5
#define DNSF_CKR_TYPE_SOA       0x6
#define DNSF_CKR_TYPE_MB        0x7
#define DNSF_CKR_TYPE_MG        0x8
#define DNSF_CKR_TYPE_MR        0x9
#define DNSF_CKR_TYPE_NULL      0xa
#define DNSF_CKR_TYPE_WKS       0xb
#define DNSF_CKR_TYPE_PTR       0xc
#define DNSF_CKR_TYPE_HINFO     0xd
#define DNSF_CKR_TYPE_MX        0xe
#define DNSF_CKR_TYPE_TXT       0xf

#define DNSF_CKR_QTYPE_AXFR     252
#define DNSF_CKR_QTYPE_MAILB    253
#define DNSF_CKR_QTYPE_MAILA    254
#define DNSF_CKR_QTYPE_4ALL     255

#define DNSF_CKR_CLASS_IN       0x1
#define DNSF_CKR_CLASS_CS       0x2
#define DNSF_CKR_CLASS_CH       0x3
#define DNSF_CKR_CLASS_HS       0x4

#define DNSF_CKR_QCLASS_ANY     255

struct dnsf_ckr_pktqsecctx {
    unsigned char qname[0xff];
    unsigned short qtype;
    unsigned short qclass;
};

struct dnsf_ckr_pktrscrecfmtctx {
    unsigned char name[0xff];
    unsigned short type;
    unsigned short clss;
    unsigned long ttl;
    unsigned short rdlen;
    unsigned char *rdata;
};

typedef struct _dnsf_ckr_pktctx {
    unsigned short id;
    unsigned char qr;
    unsigned char opcode;
    //unsigned char aatcrdra;
    unsigned char aa;
    unsigned char tc;
    unsigned char rd;
    unsigned char ra;
    unsigned char z;
    unsigned char rcode;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
    struct dnsf_ckr_pktqsecctx questionsec;
    struct dnsf_ckr_pktrscrecfmtctx rscrecfmt;
}dnsf_ckr_pktctx;

dnsf_ckr_pktctx *unpack_dns_data(const unsigned char *rawbuf, const size_t bufsz);

size_t pack_dns_data(unsigned char **output, dnsf_ckr_pktctx dnspkt);

unsigned char *dnsf_ckr_mk_dnsresponse(size_t *bufsz, const unsigned char *query, const size_t query_size, unsigned long dnsserver_addr);

#endif
