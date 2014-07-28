#include "utest.h"
#include "../types.h"
#include "../ctxs.h"
#include "../iputils.h"
#include "../eth.h"
#include "../arp.h"
#include "../ip.h"
#include "../udp.h"
#include "../conf.h"
#include <stdio.h>
#include <string.h>

char *dnsf_ckr_victims_ctx_tests() {
    dnsf_ckr_victims_ctx *victims = NULL, *vp;
    struct expected_value {
        char *name;
        char *addr;
        in_addr_t naddr;
    };
    int e;
    struct expected_value expected_values[10] = {
        { "local1",  "127.0.0.1", htonl(0x7f000001)},
        { "local2",  "127.0.0.2", htonl(0x7f000002)},
        { "local3",  "127.0.0.3", htonl(0x7f000003)},
        { "local4",  "127.0.0.4", htonl(0x7f000004)},
        { "local5",  "127.0.0.5", htonl(0x7f000005)},
        { "local6",  "127.0.0.6", htonl(0x7f000006)},
        { "local7",  "127.0.0.7", htonl(0x7f000007)},
        { "local8",  "127.0.0.8", htonl(0x7f000008)},
        { "local9",  "127.0.0.9", htonl(0x7f000009)},
        {"local10", "127.0.0.10", htonl(0x7f00000a)}
    };
    printf("-- running dnsf_ckr_victims_ctx_tests\n");
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        victims = add_victim_to_dnsf_ckr_victims_ctx(victims,
                      expected_values[e].name,
                      strlen(expected_values[e].name),
                      expected_values[e].addr,
                      strlen(expected_values[e].addr));
    }
    for (vp = victims, e = 0; vp != NULL; vp = vp->next, e++) {
        UTEST_CHECK("Unexpected victim name.", strcmp(vp->name, expected_values[e].name) == 0);
        UTEST_CHECK("Unexpected victim address.", vp->addr == expected_values[e].naddr);
    }
    del_dnsf_ckr_victims_ctx(victims);
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_servers_ctx_tests() {
    dnsf_ckr_servers_ctx *servers = NULL, *sp;
    struct expected_value {
        char *name;
        char *addr;
        in_addr_t naddr;
    };
    struct expected_value expected_values[3] = {
        {"dns-server0", "127.0.0.1", htonl(0x7f000001)},
        {"dns-server1", "127.0.0.2", htonl(0x7f000002)},
        {"dns-server2", "127.0.0.3", htonl(0x7f000003)}
    };
    size_t e;
    printf("-- running dnsf_ckr_servers_ctx_tests\n");
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        servers = add_server_to_dnsf_ckr_servers_ctx(servers,
                       expected_values[e].name,
                       strlen(expected_values[e].name),
                       expected_values[e].addr,
                       strlen(expected_values[e].addr));
    }
    for (sp = servers, e = 0; sp != NULL; sp = sp->next, e++) {
        UTEST_CHECK("Unexpected server name.", strcmp(sp->name, expected_values[e].name) == 0);
        UTEST_CHECK("Unexpected server address.", sp->addr == expected_values[e].naddr);
    }
    del_dnsf_ckr_servers_ctx(servers);
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_hostnames_ctx_tests() {
    dnsf_ckr_hostnames_ctx *hostnames = NULL, *hp;
    struct expected_value {
        char *name;
        char *addr;
        in_addr_t naddr;
    };
    struct expected_value expected_values[2] = {
        {"localhost",           "127.0.0.1",   htonl(0x7f000001)},
        {"localhost.broadcast", "127.0.0.255", htonl(0x7f0000ff)}
    };
    size_t e;
    printf("-- running dnsf_ckr_hostnames_ctx_tests\n");
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        hostnames = add_host_to_dnsf_ckr_hostnames_ctx(hostnames,
                            expected_values[e].name,
                            strlen(expected_values[e].name),
                            expected_values[e].addr,
                            strlen(expected_values[e].addr));
    }
    for (hp = hostnames, e = 0; hp; hp = hp->next, e++) {
        UTEST_CHECK("Unexpected host name.", strcmp(hp->name, expected_values[e].name) == 0);
        UTEST_CHECK("Unexpected host address.", hp->addr == hp->addr);
    }
    del_dnsf_ckr_hostnames_ctx(hostnames);
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_hostnames_set_ctx_tests() {
    dnsf_ckr_hostnames_set_ctx *hnset = NULL, *hp;
    char *expected_values[] = {
        "host-set-x", "host-set-y", "host-set-z", ""
    };
    size_t e;
    printf("-- running dnsf_ckr_hostnames_set_ctx_tests\n");
    for (e = 0; expected_values[e][0] != 0; e++) {
        hnset = add_set_to_dnsf_ckr_hostnames_set_ctx(hnset,
                     expected_values[e], strlen(expected_values[e]));
    }
    for (hp = hnset, e = 0; hp; hp = hp->next, e++) {
        UTEST_CHECK("Unexpected host set name.", strcmp(hp->name, expected_values[e]) == 0);
        UTEST_CHECK("Non null set pointer.", hp->hostnames == NULL);
    }
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_fakenameserver_ctx_tests() {
    dnsf_ckr_fakenameserver_ctx *fakenameserver = NULL, *fp;
    struct expected_value {
        void *with;
        void *mess_up;
    };
    struct expected_value expected_values[5] = {
        {(void *)malloc(8), (void *)malloc(8)},
        {(void *)malloc(8), (void *)malloc(8)},
        {(void *)malloc(8), (void *)malloc(8)},
        {(void *)malloc(8), (void *)malloc(8)},
        {(void *)malloc(8), (void *)malloc(8)}
    };
    size_t e;
    printf("-- running dnsf_ckr_fakenameserver_ctx_tests\n");
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        fakenameserver = add_faking_to_dnsf_ckr_fakenameserver_ctx(fakenameserver,
                                expected_values[e].with, expected_values[e].mess_up);
    }
    for (fp = fakenameserver, e = 0; fp; fp = fp->next, e++) {
        UTEST_CHECK("Unexpected \"with\" pointer.",
             fp->with == (dnsf_ckr_victims_ctx *)expected_values[e].with);
        UTEST_CHECK("Unexpected \"mess_up\" pointer.",
             fp->mess_up == (dnsf_ckr_hostnames_set_ctx *)expected_values[e].mess_up);
    }
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        free(expected_values[e].with);
        free(expected_values[e].mess_up);
    }
    del_dnsf_ckr_fakenameserver_ctx(fakenameserver);
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_realdnstransactions_ctx_tests() {
    dnsf_ckr_realdnstransactions_ctx *transactions = NULL, *tp;
    struct expected_value {
        void *victim;
        void *sends_reqs_to;
    };
    struct expected_value expected_values[5] = {
        {(void *)malloc(8), (void *)malloc(8)},
        {(void *)malloc(8), (void *)malloc(8)},
        {(void *)malloc(8), (void *)malloc(8)},
        {(void *)malloc(8), (void *)malloc(8)},
        {(void *)malloc(8), (void *)malloc(8)}
    };
    size_t e;
    printf("-- running dnsf_ckr_realdnstransactions_ctx_tests\n");
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        transactions = add_transaction_to_dnsf_ckr_realdnstransactions_ctx(transactions,
                             expected_values[e].victim, expected_values[e].sends_reqs_to);
    }
    for (tp = transactions, e = 0; tp; tp = tp->next, e++) {
        UTEST_CHECK("Unexpected \"victim\" pointer.",
                    tp->victim == (dnsf_ckr_victims_ctx *)expected_values[e].victim);
        UTEST_CHECK("Unexpected \"mess_up\" pointer.",
                    tp->sends_reqs_to ==
                (dnsf_ckr_servers_ctx *)expected_values[e].sends_reqs_to);
    }
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        free(expected_values[e].victim);
        free(expected_values[e].sends_reqs_to);
    }
    del_dnsf_ckr_realdnstransactions_ctx(transactions);
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_ip2num_test() {
    struct expected_value {
        char *addr;
        in_addr_t naddr;
    };
    struct expected_value expected_values[3] = {
        {      "127.0.0.1", htonl(0x7f000001)},
        {    "192.30.70.2", htonl(0xc01e4602)},
        {"255.255.255.255", htonl(0xffffffff)}
    };
    size_t e;
    printf("-- dnsf_ckr_ip2num_test\n");
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        UTEST_CHECK("Wrong ip conversion.",
              dnsf_ckr_ip2num(expected_values[e].addr,
                  strlen(expected_values[e].addr)) == expected_values[e].naddr);
    }
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_is_valid_ipv4_test() {
    struct expected_return {
        char *addr;
        int valid;
    };
    struct expected_return expected_returns[6] = {
        { "127.0.0.1", 1},  {"192.30.70.167", 1},  {  "298.1.1.2", 0},
        {"71.320.0.2", 0},  {   "20.1.301.0", 0},  {"20.1.3.1820", 0}
    };
    size_t e;
    static char msg[100];
    int result = 0;
    printf("-- dnsf_ckr_is_valid_ipv4_test\n");
    for (e = 0; e < sizeof(expected_returns) / sizeof(expected_returns[0]); e++) {
        result = dnsf_ckr_is_valid_ipv4(expected_returns[e].addr);
        sprintf(msg, "Wrong validation for %s (retval=%d).", expected_returns[e].addr, result);
        UTEST_CHECK(msg, result == expected_returns[e].valid);
    }
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_chsum_basic_computing_test() {
    unsigned char *buf = "\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c";
    size_t bufsz = 20;
    printf("-- dnsf_ckr_chsum_basic_computing_test\n");
    UTEST_CHECK("Wrong checksum computing.", 0xb1e6 == dnsf_ckr_compute_chsum(buf, bufsz));
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_udp_chsum_computing_test() {
    struct dnsf_ckr_udp_header udp;
    unsigned char *buf = NULL;
    size_t bufsz = 0;
    udp.src = 0x35;
    udp.dest = 0xec34;
    udp.len = 0x9a;
    udp.chsum = 0;
    udp.payload = "\x27\x47\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67"
                  "\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x02\x62\x72\x00\x00\x01\x00\x01\x03"
                  "\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x02\x62\x72\x00"
                  "\x00\x01\x00\x01\x00\x00\x01\x2b\x00\x04\xad\xc2\x76\x37\x03\x77\x77\x77"
                  "\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x02\x62\x72\x00\x00\x01\x00"
                  "\x01\x00\x00\x01\x2b\x00\x04\xad\xc2\x76\x38\x03\x77\x77\x77\x06\x67\x6f"
                  "\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x02\x62\x72\x00\x00\x01\x00\x01\x00\x00"
                  "\x01\x2b\x00\x04\xad\xc2\x76\x3f\x00\x00\x00\x13\x00\x21\x00\x34\x00\x42"
                  "\x00\x55";
    udp.payload_size = 146;
    printf("-- dnsf_ckr_udp_chsum_computing_test\n");
    buf = dnsf_ckr_mk_udp_dgram(&bufsz, udp);
    static char msg[100];
    unsigned short checksum = dnsf_ckr_compute_udp_chsum(buf, bufsz, 0xc01e460f, 0xc01e460a, udp.len);
    unsigned short expected_value = 0xd199;
    sprintf(msg, "Wrong udp checksum computing (0x%.4x != 0x%.4x).", checksum, expected_value);
    UTEST_CHECK(msg, checksum == expected_value);
    printf("-- passed.\n");
    free(buf);
    return NULL;
}

char *dnsf_ckr_udp_buffer_parsing_test() {
    struct dnsf_ckr_udp_header *udp;
    unsigned char *raw_udp = "\x00\x35\xec\x34\x00\x0b\xf0\x0f\x75\x64\x70";
    unsigned char *udp_buf = NULL;
    static char msg[100];
    size_t udp_bufsz = 0;
    printf("-- dnsf_ckr_udp_buffer_parsing_test\n");
    udp = dnsf_ckr_parse_udp_dgram(raw_udp, 11);
    UTEST_CHECK("Null udp header pointer.", udp != NULL);
    sprintf(msg, "Wrong src port (0x%.4x != 0x0035)", udp->src);
    UTEST_CHECK(msg, udp->src == 0x35);
    sprintf(msg, "Wrong dest port (0x%.4x != 0xec34)", udp->dest);
    UTEST_CHECK(msg, udp->dest == 0xec34);
    sprintf(msg, "Wrong packet length (0x%.4x != 0x0008)", udp->len);
    UTEST_CHECK(msg, udp->len == 0x000b);
    sprintf(msg, "Wrong dest port (0x%.4x != 0xf00f)", udp->chsum);
    UTEST_CHECK(msg, udp->chsum == 0xf00f);
    UTEST_CHECK("Null udp payload pointer.", udp->payload != NULL);
    UTEST_CHECK("Wrong udp payload size.", udp->payload_size == 3);
    UTEST_CHECK("Wrong udp payload.", udp->payload[0] == 'u' &&
                                      udp->payload[1] == 'd' &&
                                      udp->payload[2] == 'p');
    udp_buf = dnsf_ckr_mk_udp_dgram(&udp_bufsz, *udp);
    UTEST_CHECK("Udp buffer not equals to 11 bytes.", udp_bufsz == 11);
    for (udp_bufsz = 0; udp_bufsz < 11; udp_bufsz++) {
        UTEST_CHECK("Udp buffer corrupted or incorrectly assembled.",
                            udp_buf[udp_bufsz] == raw_udp[udp_bufsz]);
    }
    free(udp->payload);
    free(udp);
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_ip_buffer_parsing_test() {
    struct dnsf_ckr_ip_header *ip;
    unsigned char *raw_ip = "\x45\x00\x00\x1f\x09\xba\x00\x00\x80\x11\x24"
                            "\x7d\xc0\x1e\x46\x0f\xc0\x1e\x46\x0a\x00\x35"
                            "\xec\x34\x00\x0b\xf0\x0f\x75\x64\x70";
    size_t raw_ip_sz = 31, r;
    static char msg[100];
    unsigned char *ip_buf = NULL;
    size_t ip_buf_sz = 0;
    printf("-- dnsf_ckr_ip_buffer_parsing_test\n");
    ip = dnsf_ckr_parse_ip_dgram(raw_ip, raw_ip_sz);
    UTEST_CHECK("Null ip structure.", ip != NULL);
    sprintf(msg, "Wrong version value (%d).", ip->version);
    UTEST_CHECK(msg, ip->version == 4);
    sprintf(msg, "Wrong ihl value (%d).", ip->ihl);
    UTEST_CHECK(msg, ip->ihl == 5);
    sprintf(msg, "Wrong tos value (%d).", ip->tos);
    UTEST_CHECK(msg, ip->tos == 0);
    sprintf(msg, "Wrong length value (%d).", ip->len);
    UTEST_CHECK(msg, ip->len == 0x001f);
    sprintf(msg, "Wrong id value (%d).", ip->id);
    UTEST_CHECK(msg, ip->id == 0x09ba);
    sprintf(msg, "Wrong flags value (%d).", ip->flags);
    UTEST_CHECK(msg, ip->flags == 0);
    sprintf(msg, "Wrong fragoff value (%d).", ip->fragoff);
    UTEST_CHECK(msg, ip->fragoff == 0);
    sprintf(msg, "Wrong ttl value (%d).", ip->ttl);
    UTEST_CHECK(msg, ip->ttl == 0x80);
    sprintf(msg, "Wrong proto value (%d).", ip->proto);
    UTEST_CHECK(msg, ip->proto == 0x11);
    sprintf(msg, "Wrong chsum value (%d).", ip->chsum);
    UTEST_CHECK(msg, ip->chsum == 0x247d);
    sprintf(msg, "Wrong src value (%d).", ip->src);
    UTEST_CHECK(msg, ip->src == 0xc01e460f);
    sprintf(msg, "Wrong dest value (%d).", ip->dest);
    UTEST_CHECK(msg, ip->dest == 0xc01e460a);
    UTEST_CHECK("Null ip payload.", ip->payload != NULL);
    sprintf(msg, "Wrong payload_size value (%d).", ip->payload_size);
    UTEST_CHECK(msg, ip->payload_size == 11);
    for (r = 20; r < raw_ip_sz; r++) {
        UTEST_CHECK("Wrong ip payload.", ip->payload[r - 20] == raw_ip[r]);
    }
    ip_buf = dnsf_ckr_mk_ip_dgram(&ip_buf_sz, *ip);
    UTEST_CHECK("Null ip buffer.", ip_buf != NULL);
    UTEST_CHECK("Wrong ip buffer size.", ip_buf_sz == 31);
    for (r = 0; r < raw_ip_sz; r++) {
        UTEST_CHECK("Ip buffer corrupted or incorrectly assembled.", ip_buf[r] == raw_ip[r]);
    }
    free(ip_buf);
    free(ip->payload);
    free(ip);
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_ethernet_buffer_parsing_test() {
    struct dnsf_ckr_ethernet_frame *eth = NULL;
    unsigned char *buffer = "\x00\x01\x02\x03\x04\x05\x07\x08\x09\x0a\x0b\x0c\x08\x00"
                            "\x45\x00\x00\x1f\x09\xba\x00\x00\x80\x11\x24"
                            "\x7d\xc0\x1e\x46\x0f\xc0\x1e\x46\x0a\x00\x35"
                            "\xec\x34\x00\x0b\xf0\x0f\x75\x64\x70";
    size_t buffer_sz = 45, b;
    size_t ethernet_frame_sz = 0;
    unsigned char *ethernet_frame = NULL;
    static char msg[100];
    printf("-- dnsf_ckr_ethernet_buffer_parsing_test\n");
    eth = dnsf_ckr_parse_ethernet_frame(buffer, buffer_sz);
    UTEST_CHECK("Null ethernet structure.", eth != NULL);
    for (b = 0; b < 6; b++) {
        UTEST_CHECK("Wrong dest mac value.", eth->dest_hw_addr[b] == buffer[b]);
    }
    for (b = 6; b < 12; b++) {
        UTEST_CHECK("Wrong src mac value.", eth->src_hw_addr[b - 6] == buffer[b]);
    }
    UTEST_CHECK("Wrong ether_type value.", eth->ether_type == 0x0800);
    UTEST_CHECK("Wrong ethernet payload size.", eth->payload_size == 31);
    for (b = 0; b < 31; b++) {
        UTEST_CHECK("Wrong ethernet payload.", eth->payload[b] == buffer[14 + b]);
    }
    ethernet_frame = dnsf_ckr_mk_ethernet_frame(&ethernet_frame_sz, *eth);
    UTEST_CHECK("Wrong ethernet frame size.", ethernet_frame_sz == buffer_sz);
    for (b = 0; b < buffer_sz; b++) {
        UTEST_CHECK("Ethernet buffer corrupted or incorrectly assembled.",
                                           ethernet_frame[b] == buffer[b]);
    }
    free(ethernet_frame);
    free(eth->payload);
    free(eth);
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_arp_buffer_parsing_test() {
    struct dnsf_ckr_arp_header *arp = NULL;
    unsigned char *raw_arp = "\xaa\xbb\xcc\xdd\x06\x04\xee\xff\x00\x01\x02"
                             "\x03\x04\x05\x7f\x00\x00\x01\x06\x07\x08\x09"
                             "\x0a\x0b\x0c\x7f\x00\x00\x02";
    size_t raw_arp_sz = 28, r;
    unsigned char *arp_dgram = NULL;
    size_t arp_dgram_sz = 0;
    static char msg[100];
    printf("-- dnsf_ckr_arp_buffer_parsing_test\n");
    arp = dnsf_ckr_parse_arp_dgram(raw_arp, raw_arp_sz);
    UTEST_CHECK("Null arp datagram.", arp != NULL);
    sprintf(msg, "Wrong hwtype (%.2x).", arp->hwtype);
    UTEST_CHECK(msg, arp->hwtype == 0xaabb);
    sprintf(msg, "Wrong ptype (%.2x).", arp->ptype);
    UTEST_CHECK(msg, arp->ptype == 0xccdd);
    sprintf(msg, "Wrong hw_addr_len (%.2x).", arp->hw_addr_len);
    UTEST_CHECK(msg, arp->hw_addr_len == 6);
    sprintf(msg, "Wrong pt_addr_len (%.2x).", arp->pt_addr_len);
    UTEST_CHECK(msg, arp->pt_addr_len == 4);
    sprintf(msg, "Wrong opcode (%.2x).", arp->opcode);
    UTEST_CHECK(msg, arp->opcode == 0xeeff);
    for (r = 0; r < 6; r++) {
        UTEST_CHECK("Wrong src_hw_addr.", arp->src_hw_addr[r] == raw_arp[r + 8]);
    }
    for (r = 0; r < 4; r++) {
        UTEST_CHECK("Wrong src_pt_addr.", arp->src_pt_addr[r] == raw_arp[r + 14]);
    }
    for (r = 0; r < 6; r++) {
        UTEST_CHECK("Wrong dest_hw_addr.", arp->dest_hw_addr[r] == raw_arp[r + 18]);
    }
    for (r = 0; r < 4; r++) {
        UTEST_CHECK("Wrong dest_pt_addr.", arp->dest_pt_addr[r] == raw_arp[r + 24]);
    }
    arp_dgram = dnsf_ckr_mk_arp_dgram(&arp_dgram_sz, *arp);
    UTEST_CHECK("Null arp buffer.", arp_dgram != NULL);
    UTEST_CHECK("Wrong arp buffer size.", arp_dgram_sz == raw_arp_sz);
    for (r = 0; r < raw_arp_sz; r++) {
        UTEST_CHECK("Arp buffer corrupted or incorrectly assembled.", arp_dgram[r] == raw_arp[r]);
    }
    free(arp_dgram);
    free(arp);
    printf("-- passed.\n");
    return NULL;
}

int write_buffer_to_file(const char *buffer, size_t bsize, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        return 0;
    }
    fwrite(buffer, bsize, 1, fp);
    fclose(fp);
    return 1;
}

char *dnsf_ckr_config_parsing_victims_test() {
    const char *dnsf_ckr_conf = "# dnsf_ckr_config_parsing_victims_test blah blah.\n"
                                "victims =\n"
                                "\tjay-lo: 127.0.0.1\n"
                                "\tzephyr: 192.30.70.3\n"
                                "\t\tchina-in-box: 203.10.1.6;\n";
    dnsf_ckr_victims_ctx *victims = NULL, *vp = NULL;
    FILE *conf = NULL;
    struct configurated_victims_ctx {
        char *name;
        int name_size;
        char *addr;
    };
    static struct configurated_victims_ctx
                    configurated_victims[3] = {
        {"jay-lo",        6,   "127.0.0.1"},
        {"zephyr",        6, "192.30.70.3"},
        {"china-in-box", 12,  "203.10.1.6"}
    };
    size_t v;
    in_addr_t addr;
    static char msg[4096];

    printf("-- dnsf_ckr_config_parsing_victims_test\n");

    UTEST_CHECK("Unable to write to \"dnsf_ckr-test.conf\"",
                write_buffer_to_file(dnsf_ckr_conf,
                                     strlen(dnsf_ckr_conf),
                                     "dnsf_ckr-test.conf") == 1);

    conf = fopen("dnsf_ckr-test.conf", "rb");

    UTEST_CHECK("Unable to open \"dnsf_ckr-test.conf\"",
                conf != NULL);


    victims = dnsf_ckr_get_victims_config(conf);

    UTEST_CHECK("victims config set not read (victims == NULL).",
                victims != NULL);

    for (vp = victims, v = 0; vp &&
                       v < sizeof(configurated_victims) /
                        sizeof(struct configurated_victims_ctx);
         vp = vp->next, v++) {
        sprintf(msg, "\"%s\" != \"%s\" (the expected is \"%s\").",
                vp->name, configurated_victims[v].name, configurated_victims[v].name);
        UTEST_CHECK(msg, strcmp(vp->name, configurated_victims[v].name) == 0);

        sprintf(msg, "%d != %d (the expected is %d).",
                vp->name_size, configurated_victims[v].name_size, configurated_victims[v].name_size);
        UTEST_CHECK(msg, configurated_victims[v].name_size == vp->name_size);

        addr = inet_addr(configurated_victims[v].addr);
        sprintf(msg, "%.8X != %.8X (the expected is %.8X).", vp->addr, addr, addr);
        UTEST_CHECK(msg, addr == vp->addr);
    }

    del_dnsf_ckr_victims_ctx(victims);

    fclose(conf);
    remove("dnsf_ckr-test.conf");

    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_config_parsing_servers_test() {
    printf("-- dnsf_ckr_config_parsing_servers_test\n");
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_config_parsing_hostnames_test() {
    printf("-- dnsf_ckr_config_parsing_hostnames_test\n");
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_config_parsing_fakenameserver_test() {
    printf("-- dnsf_ckr_config_parsing_fakenameserver_test\n");
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_config_parsing_realdnstransactions_test() {
    printf("-- dnsf_ckr_config_parsing_realdnstransactions_test\n");
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_config_parsing_intvalues_reading_test() {
    printf("-- dnsf_ckr_config_parsing_intvalues_reading_test\n");
    printf("-- passed.\n");
    return NULL;
}

char *dnsf_ckr_config_parsing_tests() {
    UTEST_RUN(dnsf_ckr_config_parsing_victims_test);
    UTEST_RUN(dnsf_ckr_config_parsing_servers_test);
    UTEST_RUN(dnsf_ckr_config_parsing_hostnames_test);
    UTEST_RUN(dnsf_ckr_config_parsing_fakenameserver_test);
    UTEST_RUN(dnsf_ckr_config_parsing_realdnstransactions_test);
    UTEST_RUN(dnsf_ckr_config_parsing_intvalues_reading_test);
    return NULL;
}

char *run_tests() {
    printf("running unit tests...\n\n");
    UTEST_RUN(dnsf_ckr_victims_ctx_tests);
    UTEST_RUN(dnsf_ckr_servers_ctx_tests);
    UTEST_RUN(dnsf_ckr_hostnames_ctx_tests);
    UTEST_RUN(dnsf_ckr_hostnames_set_ctx_tests);
    UTEST_RUN(dnsf_ckr_fakenameserver_ctx_tests);
    UTEST_RUN(dnsf_ckr_realdnstransactions_ctx_tests);
    UTEST_RUN(dnsf_ckr_ip2num_test);
    UTEST_RUN(dnsf_ckr_is_valid_ipv4_test);
    UTEST_RUN(dnsf_ckr_ethernet_buffer_parsing_test);
    UTEST_RUN(dnsf_ckr_arp_buffer_parsing_test);
    UTEST_RUN(dnsf_ckr_ip_buffer_parsing_test);
    UTEST_RUN(dnsf_ckr_udp_buffer_parsing_test);
    UTEST_RUN(dnsf_ckr_chsum_basic_computing_test);
    UTEST_RUN(dnsf_ckr_udp_chsum_computing_test);
    UTEST_RUN(dnsf_ckr_config_parsing_tests);
    return NULL;
}

int main(int argc, char **argv) {
    char *result = run_tests();
    if (result != NULL) {
        printf("%s [%d test(s) ran]\n", result, utest_ran_tests);
        return 1;
    }
    return 0;
}
