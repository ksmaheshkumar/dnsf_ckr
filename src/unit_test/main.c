#include "../types.h"
#include "../ctxs.h"
#include "../iputils.h"
#include "../eth.h"
#include "../arp.h"
#include "../ip.h"
#include "../udp.h"
#include "../conf.h"
#include <cutest.h>
#include <stdio.h>
#include <string.h>

CUTE_TEST_CASE(dnsf_ckr_victims_ctx_tests)
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
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        victims = add_victim_to_dnsf_ckr_victims_ctx(victims,
                      expected_values[e].name,
                      strlen(expected_values[e].name),
                      expected_values[e].addr,
                      strlen(expected_values[e].addr));
    }
    for (vp = victims, e = 0; vp != NULL; vp = vp->next, e++) {
        CUTE_CHECK("Unexpected victim name.", strcmp(vp->name, expected_values[e].name) == 0);
        CUTE_CHECK("Unexpected victim address.", vp->addr == expected_values[e].naddr);
    }
    del_dnsf_ckr_victims_ctx(victims);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_servers_ctx_tests)
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
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        servers = add_server_to_dnsf_ckr_servers_ctx(servers,
                       expected_values[e].name,
                       strlen(expected_values[e].name),
                       expected_values[e].addr,
                       strlen(expected_values[e].addr));
    }
    for (sp = servers, e = 0; sp != NULL; sp = sp->next, e++) {
        CUTE_CHECK("Unexpected server name.", strcmp(sp->name, expected_values[e].name) == 0);
        CUTE_CHECK("Unexpected server address.", sp->addr == expected_values[e].naddr);
    }
    del_dnsf_ckr_servers_ctx(servers);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_hostnames_ctx_tests)
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
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        hostnames = add_host_to_dnsf_ckr_hostnames_ctx(hostnames,
                            expected_values[e].name,
                            strlen(expected_values[e].name),
                            expected_values[e].addr,
                            strlen(expected_values[e].addr));
    }
    for (hp = hostnames, e = 0; hp; hp = hp->next, e++) {
        CUTE_CHECK("Unexpected host name.", strcmp(hp->name, expected_values[e].name) == 0);
        CUTE_CHECK("Unexpected host address.", hp->addr == hp->addr);
    }
    del_dnsf_ckr_hostnames_ctx(hostnames);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_hostnames_set_ctx_tests)
    dnsf_ckr_hostnames_set_ctx *hnset = NULL, *hp;
    char *expected_values[] = {
        "host-set-x", "host-set-y", "host-set-z", ""
    };
    size_t e;
    for (e = 0; expected_values[e][0] != 0; e++) {
        hnset = add_set_to_dnsf_ckr_hostnames_set_ctx(hnset,
                     expected_values[e], strlen(expected_values[e]));
    }
    for (hp = hnset, e = 0; hp; hp = hp->next, e++) {
        CUTE_CHECK("Unexpected host set name.", strcmp(hp->name, expected_values[e]) == 0);
        CUTE_CHECK("Non null set pointer.", hp->hostnames == NULL);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_fakenameserver_ctx_tests)
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
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        fakenameserver = add_faking_to_dnsf_ckr_fakenameserver_ctx(fakenameserver,
                                expected_values[e].with, expected_values[e].mess_up);
    }
    for (fp = fakenameserver, e = 0; fp; fp = fp->next, e++) {
        CUTE_CHECK("Unexpected \"with\" pointer.",
             fp->with == (dnsf_ckr_victims_ctx *)expected_values[e].with);
        CUTE_CHECK("Unexpected \"mess_up\" pointer.",
             fp->mess_up == (dnsf_ckr_hostnames_set_ctx *)expected_values[e].mess_up);
    }
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        free(expected_values[e].with);
        free(expected_values[e].mess_up);
    }
    del_dnsf_ckr_fakenameserver_ctx(fakenameserver);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_realdnstransactions_ctx_tests)
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
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        transactions = add_transaction_to_dnsf_ckr_realdnstransactions_ctx(transactions,
                             expected_values[e].victim, expected_values[e].sends_reqs_to);
    }
    for (tp = transactions, e = 0; tp; tp = tp->next, e++) {
        CUTE_CHECK("Unexpected \"victim\" pointer.",
                    tp->victim == (dnsf_ckr_victims_ctx *)expected_values[e].victim);
        CUTE_CHECK("Unexpected \"mess_up\" pointer.",
                    tp->sends_reqs_to ==
                (dnsf_ckr_servers_ctx *)expected_values[e].sends_reqs_to);
    }
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        free(expected_values[e].victim);
        free(expected_values[e].sends_reqs_to);
    }
    del_dnsf_ckr_realdnstransactions_ctx(transactions);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_ip2num_test)
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
    for (e = 0; e < sizeof(expected_values) / sizeof(expected_values[0]); e++) {
        CUTE_CHECK("Wrong ip conversion.",
              dnsf_ckr_ip2num(expected_values[e].addr,
                  strlen(expected_values[e].addr)) == expected_values[e].naddr);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_is_valid_ipv4_test)
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
    for (e = 0; e < sizeof(expected_returns) / sizeof(expected_returns[0]); e++) {
        result = dnsf_ckr_is_valid_ipv4(expected_returns[e].addr);
        sprintf(msg, "Wrong validation for %s (retval=%d).", expected_returns[e].addr, result);
        CUTE_CHECK(msg, result == expected_returns[e].valid);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_chsum_basic_computing_test)
    unsigned char *buf = "\x45\x00\x00\x3c\x1c\x46\x40\x00\x40\x06\x00\x00\xac\x10\x0a\x63\xac\x10\x0a\x0c";
    size_t bufsz = 20;
    CUTE_CHECK("Wrong checksum computing.", 0xb1e6 == dnsf_ckr_compute_chsum(buf, bufsz));
    return NULL;
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_udp_chsum_computing_test)
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
    buf = dnsf_ckr_mk_udp_dgram(&bufsz, udp);
    static char msg[100];
    unsigned short checksum = dnsf_ckr_compute_udp_chsum(buf, bufsz, 0xc01e460f, 0xc01e460a, udp.len);
    unsigned short expected_value = 0xd199;
    sprintf(msg, "Wrong udp checksum computing (0x%.4x != 0x%.4x).", checksum, expected_value);
    CUTE_CHECK(msg, checksum == expected_value);
    free(buf);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_udp_buffer_parsing_test)
    struct dnsf_ckr_udp_header *udp;
    unsigned char *raw_udp = "\x00\x35\xec\x34\x00\x0b\xf0\x0f\x75\x64\x70";
    unsigned char *udp_buf = NULL;
    static char msg[100];
    size_t udp_bufsz = 0;
    udp = dnsf_ckr_parse_udp_dgram(raw_udp, 11);
    CUTE_CHECK("Null udp header pointer.", udp != NULL);
    sprintf(msg, "Wrong src port (0x%.4x != 0x0035)", udp->src);
    CUTE_CHECK(msg, udp->src == 0x35);
    sprintf(msg, "Wrong dest port (0x%.4x != 0xec34)", udp->dest);
    CUTE_CHECK(msg, udp->dest == 0xec34);
    sprintf(msg, "Wrong packet length (0x%.4x != 0x0008)", udp->len);
    CUTE_CHECK(msg, udp->len == 0x000b);
    sprintf(msg, "Wrong dest port (0x%.4x != 0xf00f)", udp->chsum);
    CUTE_CHECK(msg, udp->chsum == 0xf00f);
    CUTE_CHECK("Null udp payload pointer.", udp->payload != NULL);
    CUTE_CHECK("Wrong udp payload size.", udp->payload_size == 3);
    CUTE_CHECK("Wrong udp payload.", udp->payload[0] == 'u' &&
                                      udp->payload[1] == 'd' &&
                                      udp->payload[2] == 'p');
    udp_buf = dnsf_ckr_mk_udp_dgram(&udp_bufsz, *udp);
    CUTE_CHECK("Udp buffer not equals to 11 bytes.", udp_bufsz == 11);
    for (udp_bufsz = 0; udp_bufsz < 11; udp_bufsz++) {
        CUTE_CHECK("Udp buffer corrupted or incorrectly assembled.",
                            udp_buf[udp_bufsz] == raw_udp[udp_bufsz]);
    }
    free(udp->payload);
    free(udp);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_ip_buffer_parsing_test)
    struct dnsf_ckr_ip_header *ip;
    unsigned char *raw_ip = "\x45\x00\x00\x1f\x09\xba\x00\x00\x80\x11\x24"
                            "\x7d\xc0\x1e\x46\x0f\xc0\x1e\x46\x0a\x00\x35"
                            "\xec\x34\x00\x0b\xf0\x0f\x75\x64\x70";
    size_t raw_ip_sz = 31, r;
    static char msg[100];
    unsigned char *ip_buf = NULL;
    size_t ip_buf_sz = 0;
    ip = dnsf_ckr_parse_ip_dgram(raw_ip, raw_ip_sz);
    CUTE_CHECK("Null ip structure.", ip != NULL);
    sprintf(msg, "Wrong version value (%d).", ip->version);
    CUTE_CHECK(msg, ip->version == 4);
    sprintf(msg, "Wrong ihl value (%d).", ip->ihl);
    CUTE_CHECK(msg, ip->ihl == 5);
    sprintf(msg, "Wrong tos value (%d).", ip->tos);
    CUTE_CHECK(msg, ip->tos == 0);
    sprintf(msg, "Wrong length value (%d).", ip->len);
    CUTE_CHECK(msg, ip->len == 0x001f);
    sprintf(msg, "Wrong id value (%d).", ip->id);
    CUTE_CHECK(msg, ip->id == 0x09ba);
    sprintf(msg, "Wrong flags value (%d).", ip->flags);
    CUTE_CHECK(msg, ip->flags == 0);
    sprintf(msg, "Wrong fragoff value (%d).", ip->fragoff);
    CUTE_CHECK(msg, ip->fragoff == 0);
    sprintf(msg, "Wrong ttl value (%d).", ip->ttl);
    CUTE_CHECK(msg, ip->ttl == 0x80);
    sprintf(msg, "Wrong proto value (%d).", ip->proto);
    CUTE_CHECK(msg, ip->proto == 0x11);
    sprintf(msg, "Wrong chsum value (%d).", ip->chsum);
    CUTE_CHECK(msg, ip->chsum == 0x247d);
    sprintf(msg, "Wrong src value (%d).", ip->src);
    CUTE_CHECK(msg, ip->src == 0xc01e460f);
    sprintf(msg, "Wrong dest value (%d).", ip->dest);
    CUTE_CHECK(msg, ip->dest == 0xc01e460a);
    CUTE_CHECK("Null ip payload.", ip->payload != NULL);
    sprintf(msg, "Wrong payload_size value (%d).", ip->payload_size);
    CUTE_CHECK(msg, ip->payload_size == 11);
    for (r = 20; r < raw_ip_sz; r++) {
        CUTE_CHECK("Wrong ip payload.", ip->payload[r - 20] == raw_ip[r]);
    }
    ip_buf = dnsf_ckr_mk_ip_dgram(&ip_buf_sz, *ip);
    CUTE_CHECK("Null ip buffer.", ip_buf != NULL);
    CUTE_CHECK("Wrong ip buffer size.", ip_buf_sz == 31);
    for (r = 0; r < raw_ip_sz; r++) {
        CUTE_CHECK("Ip buffer corrupted or incorrectly assembled.", ip_buf[r] == raw_ip[r]);
    }
    free(ip_buf);
    free(ip->payload);
    free(ip);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_ethernet_buffer_parsing_test)
    struct dnsf_ckr_ethernet_frame *eth = NULL;
    unsigned char *buffer = "\x00\x01\x02\x03\x04\x05\x07\x08\x09\x0a\x0b\x0c\x08\x00"
                            "\x45\x00\x00\x1f\x09\xba\x00\x00\x80\x11\x24"
                            "\x7d\xc0\x1e\x46\x0f\xc0\x1e\x46\x0a\x00\x35"
                            "\xec\x34\x00\x0b\xf0\x0f\x75\x64\x70";
    size_t buffer_sz = 45, b;
    size_t ethernet_frame_sz = 0;
    unsigned char *ethernet_frame = NULL;
    static char msg[100];
    eth = dnsf_ckr_parse_ethernet_frame(buffer, buffer_sz);
    CUTE_CHECK("Null ethernet structure.", eth != NULL);
    for (b = 0; b < 6; b++) {
        CUTE_CHECK("Wrong dest mac value.", eth->dest_hw_addr[b] == buffer[b]);
    }
    for (b = 6; b < 12; b++) {
        CUTE_CHECK("Wrong src mac value.", eth->src_hw_addr[b - 6] == buffer[b]);
    }
    CUTE_CHECK("Wrong ether_type value.", eth->ether_type == 0x0800);
    CUTE_CHECK("Wrong ethernet payload size.", eth->payload_size == 31);
    for (b = 0; b < 31; b++) {
        CUTE_CHECK("Wrong ethernet payload.", eth->payload[b] == buffer[14 + b]);
    }
    ethernet_frame = dnsf_ckr_mk_ethernet_frame(&ethernet_frame_sz, *eth);
    CUTE_CHECK("Wrong ethernet frame size.", ethernet_frame_sz == buffer_sz);
    for (b = 0; b < buffer_sz; b++) {
        CUTE_CHECK("Ethernet buffer corrupted or incorrectly assembled.",
                                           ethernet_frame[b] == buffer[b]);
    }
    free(ethernet_frame);
    free(eth->payload);
    free(eth);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_arp_buffer_parsing_test)
    struct dnsf_ckr_arp_header *arp = NULL;
    unsigned char *raw_arp = "\xaa\xbb\xcc\xdd\x06\x04\xee\xff\x00\x01\x02"
                             "\x03\x04\x05\x7f\x00\x00\x01\x06\x07\x08\x09"
                             "\x0a\x0b\x0c\x7f\x00\x00\x02";
    size_t raw_arp_sz = 28, r;
    unsigned char *arp_dgram = NULL;
    size_t arp_dgram_sz = 0;
    static char msg[100];
    arp = dnsf_ckr_parse_arp_dgram(raw_arp, raw_arp_sz);
    CUTE_CHECK("Null arp datagram.", arp != NULL);
    sprintf(msg, "Wrong hwtype (%.2x).", arp->hwtype);
    CUTE_CHECK(msg, arp->hwtype == 0xaabb);
    sprintf(msg, "Wrong ptype (%.2x).", arp->ptype);
    CUTE_CHECK(msg, arp->ptype == 0xccdd);
    sprintf(msg, "Wrong hw_addr_len (%.2x).", arp->hw_addr_len);
    CUTE_CHECK(msg, arp->hw_addr_len == 6);
    sprintf(msg, "Wrong pt_addr_len (%.2x).", arp->pt_addr_len);
    CUTE_CHECK(msg, arp->pt_addr_len == 4);
    sprintf(msg, "Wrong opcode (%.2x).", arp->opcode);
    CUTE_CHECK(msg, arp->opcode == 0xeeff);
    for (r = 0; r < 6; r++) {
        CUTE_CHECK("Wrong src_hw_addr.", arp->src_hw_addr[r] == raw_arp[r + 8]);
    }
    for (r = 0; r < 4; r++) {
        CUTE_CHECK("Wrong src_pt_addr.", arp->src_pt_addr[r] == raw_arp[r + 14]);
    }
    for (r = 0; r < 6; r++) {
        CUTE_CHECK("Wrong dest_hw_addr.", arp->dest_hw_addr[r] == raw_arp[r + 18]);
    }
    for (r = 0; r < 4; r++) {
        CUTE_CHECK("Wrong dest_pt_addr.", arp->dest_pt_addr[r] == raw_arp[r + 24]);
    }
    arp_dgram = dnsf_ckr_mk_arp_dgram(&arp_dgram_sz, *arp);
    CUTE_CHECK("Null arp buffer.", arp_dgram != NULL);
    CUTE_CHECK("Wrong arp buffer size.", arp_dgram_sz == raw_arp_sz);
    for (r = 0; r < raw_arp_sz; r++) {
        CUTE_CHECK("Arp buffer corrupted or incorrectly assembled.", arp_dgram[r] == raw_arp[r]);
    }
    free(arp_dgram);
    free(arp);
CUTE_TEST_CASE_END

int write_buffer_to_file(const char *buffer, size_t bsize, const char *filename) {
    FILE *fp = fopen(filename, "wb");
    if (fp == NULL) {
        return 0;
    }
    fwrite(buffer, bsize, 1, fp);
    fclose(fp);
    return 1;
}

CUTE_TEST_CASE(dnsf_ckr_config_parsing_victims_test)
    const char *dnsf_ckr_conf = "# dnsf_ckr_config_parsing_victims_test blah blah.\n"
                                "victims =\n"
                                "\tjay-lo: 127.0.0.1\n"
                                "\tzephyr: 192.30.70.3\n"
                                "\t\tchina-in-box: 203.10.1.6;\n";
    dnsf_ckr_victims_ctx *victims = NULL, *vp = NULL;
    FILE *conf = NULL;
    struct configurated_victims_ctx {
        char *name;
        size_t name_size;
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

    CUTE_CHECK("Unable to write to \"dnsf_ckr-test.conf\"",
                write_buffer_to_file(dnsf_ckr_conf,
                                     strlen(dnsf_ckr_conf),
                                     "dnsf_ckr-test.conf") == 1);

    conf = fopen("dnsf_ckr-test.conf", "rb");

    CUTE_CHECK("Unable to open \"dnsf_ckr-test.conf\"",
                conf != NULL);


    victims = dnsf_ckr_get_victims_config(conf);

    CUTE_CHECK("victims config set not read (victims == NULL).",
                victims != NULL);

    for (vp = victims, v = 0; vp &&
                       v < sizeof(configurated_victims) /
                        sizeof(struct configurated_victims_ctx);
         vp = vp->next, v++) {
        sprintf(msg, "\"%s\" != \"%s\" (the expected is \"%s\").",
                vp->name, configurated_victims[v].name, configurated_victims[v].name);
        CUTE_CHECK(msg, strcmp(vp->name, configurated_victims[v].name) == 0);

        sprintf(msg, "%d != %d (the expected is %d).",
                vp->name_size, configurated_victims[v].name_size, configurated_victims[v].name_size);
        CUTE_CHECK(msg, configurated_victims[v].name_size == vp->name_size);

        addr = inet_addr(configurated_victims[v].addr);
        sprintf(msg, "%.8X != %.8X (the expected is %.8X).", vp->addr, addr, addr);
        CUTE_CHECK(msg, addr == vp->addr);
    }

    CUTE_CHECK("((((((There are some untested data))))))", v == sizeof(configurated_victims) /
                                                            sizeof(struct configurated_victims_ctx));

    del_dnsf_ckr_victims_ctx(victims);

    fclose(conf);
    remove("dnsf_ckr-test.conf");

CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_config_parsing_servers_test)
    const char *dnsf_ckr_config_data = "dns-servers = the-good: 192.30.70.15\n"
                                       "the-bad: 192.30.70.16\nthe-ugly: 192.30.70.17;";
    dnsf_ckr_servers_ctx *servers = NULL, *sp = NULL;
    struct expected_server_data_ctx {
        char *name;
        size_t name_size;
        char *addr;
    };
    struct expected_server_data_ctx expected_server_data[3] = {
        {"the-good", 8, "192.30.70.15"},
        { "the-bad", 7, "192.30.70.16"},
        {"the-ugly", 8, "192.30.70.17"}
    };
    in_addr_t addr;
    size_t e;
    FILE *conf = NULL;
    static char msg[255];
    CUTE_CHECK("Unable to write to \"dnsf_ckr-test.conf\"",
                write_buffer_to_file(dnsf_ckr_config_data,
                                     strlen(dnsf_ckr_config_data),
                                     "dnsf_ckr-test.conf") == 1);
    conf = fopen("dnsf_ckr-test.conf", "rb");
    CUTE_CHECK("Unable to open \"dnsf_ckr-test.conf\"", conf != NULL);
    servers = dnsf_ckr_get_servers_config(conf);
    CUTE_CHECK("servers == NULL", servers != NULL);
    for (e = 0, sp = servers; sp != NULL && e < sizeof(expected_server_data) /
                                                sizeof(struct expected_server_data_ctx); e++, sp = sp->next) {
        sprintf(msg, "\"%s\" != \"%s\" (the expected is \"%s\").", sp->name, expected_server_data[e].name,
                                                                   expected_server_data[e].name);
        CUTE_CHECK(msg, strcmp(sp->name, expected_server_data[e].name) == 0);
        sprintf(msg, "%d != %d (the expected is %d).", sp->name_size, expected_server_data[e].name_size,
                                                       expected_server_data[e].name_size);
        CUTE_CHECK(msg, sp->name_size == expected_server_data[e].name_size);
        addr = inet_addr(expected_server_data[e].addr);
        sprintf(msg, "%.8X != %.8X (the expected is %.8X).", sp->addr, addr, addr);
        CUTE_CHECK(msg, sp->addr == addr);
    }
    CUTE_CHECK("((((((There is some untested data))))))", e == sizeof(expected_server_data) /
                                                            sizeof(struct expected_server_data_ctx));

    del_dnsf_ckr_servers_ctx(servers);
    fclose(conf);
    remove("dnsf_ckr-test.conf");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_config_parsing_hostnames_test)
    const char *data = "namelist set_01 = \n\twww.xkcd.com: 127.0.0.1\n\tgithub.com:127.0.0.2\n\twww.reddit.com:127.0.0.3\n\twww.qotsa.com: 127.0.0.4\n;\n"
                       "namelist set_02 = \n\tcat-v.org:127.0.0.5\n\twww.opensource.org:127.0.0.6\n\twww.linux.org: 127.0.0.7\n\twww.apple.com: 127.0.0.8\n;\n"
                       "namelist set_03 = \n\twww.blackkeys.com: 127.0.0.9\n\twww.valgrind.org: 127.0.0.10\n;\n";
    FILE *config = NULL;
    struct set_data_ctx {
        char *setname;
        char *domain;
        size_t dsize;
        char *addr;
    };
    dnsf_ckr_hostnames_set_ctx *hostnames = NULL, *hp = NULL;
    dnsf_ckr_hostnames_ctx *hpp = NULL;
    size_t h;
    in_addr_t addr;
    static char msg[255] = "";
    struct set_data_ctx set_data[11] = {
        {"set_01", "www.xkcd.com",       12, "127.0.0.1"},
        {"set_01", "github.com",         10, "127.0.0.2"},
        {"set_01", "www.reddit.com",     14, "127.0.0.3"},
        {"set_01", "www.qotsa.com",      13, "127.0.0.4"},
        {"set_02", "cat-v.org",           9, "127.0.0.5"},
        {"set_02", "www.opensource.org", 18, "127.0.0.6"},
        {"set_02", "www.linux.org",      13, "127.0.0.7"},
        {"set_02", "www.apple.com",      13, "127.0.0.8"},
        {"set_03", "www.blackkeys.com",  17, "127.0.0.9"},
        {"set_03", "www.valgrind.org",   16, "127.0.0.10"}
    };
    CUTE_CHECK("Unable to write to \"dnsf_ckr-test.conf\"",
                write_buffer_to_file(data,
                                     strlen(data),
                                     "dnsf_ckr-test.conf") == 1);
    config = fopen("dnsf_ckr-test.conf", "rb");
    hostnames = dnsf_ckr_get_hostnames_config(config);
    fclose(config);
    remove("dnsf_ckr-test.conf");
    CUTE_CHECK("hostnames == NULL", hostnames != NULL);
    h = 0;
    for (hp = hostnames; hp; hp = hp->next) {
        h++;
    }
    CUTE_CHECK("h != 3", h == 3);
    h = 0;
    for (hp = hostnames; hp; hp = hp->next) {
        for (hpp = hp->hostnames; hpp; hpp = hpp->next) {
            sprintf(msg, "wrong set name [expected:%s]", set_data[h].setname);
            CUTE_CHECK(msg, strcmp(hp->name, set_data[h].setname) == 0);
            sprintf(msg, "wrong domain name [expected:%s]", set_data[h].domain);
            CUTE_CHECK(msg, strcmp(hpp->name, set_data[h].domain) == 0);
            sprintf(msg, "wrong domain name size [expected:%d]", set_data[h].dsize);
            CUTE_CHECK(msg, hpp->name_size == set_data[h].dsize);
            addr = inet_addr(set_data[h].addr);
            sprintf(msg, "wrong addrinfo [expected:0x%.8x]", set_data[h].addr);
            CUTE_CHECK(msg, hpp->addr == addr);
            h++;
        }
    }
    del_dnsf_ckr_hostnames_set_ctx(hostnames);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_config_parsing_fakenameserver_test)
    dnsf_ckr_hostnames_set_ctx *hostnames = NULL, *hp = NULL;
    dnsf_ckr_victims_ctx *victims = NULL, *vp = NULL;
    dnsf_ckr_fakenameserver_ctx *fakenameserver = NULL, *fp = NULL;
    const char *config_data = "namelist test-names = \n"
                              "\twww.xkcd.com: 127.0.0.1\n"
                              "\twww.amazon.com: 127.0.0.2\n"
                              ";\n"
                              "namelist local-names = \n"
                              "\tswap: 172.16.0.171\n"
                              "\thoder: 192.168.7.170\n"
                              ";\n"
                              "victims = \n"
                              "\tpenelope: 192.30.70.7\n"
                              "\twork-machine: 192.168.7.140\n"
                              "\told-work-machine: 192.168.7.89\n"
                              ";\n"
                              "fake-nameserver = \n"
                              "\twith penelope mess up test-names\n"
                              "\twith work-machine mess up local-names\n"
                              "\twith old-work-machine mess up test-names, local-names\n"
                              ";";
    FILE *config = NULL;
    CUTE_CHECK("Unable to write to \"dnsf_ckr-test.conf\"",
                write_buffer_to_file(config_data,
                                     strlen(config_data),
                                     "dnsf_ckr-test.conf") == 1);
    config = fopen("dnsf_ckr-test.conf", "rb");
    CUTE_CHECK("config == NULL", config != NULL);
    victims = dnsf_ckr_get_victims_config(config);
    CUTE_CHECK("victims == NULL", victims != NULL);
    hostnames = dnsf_ckr_get_hostnames_config(config);
    CUTE_CHECK("hostnames == NULL", hostnames != NULL);
    fakenameserver = dnsf_ckr_get_fakenameserver_config(config, victims, hostnames);

    fp = fakenameserver;

    CUTE_CHECK("fp == NULL", fp != NULL);
    hp = get_dnsf_ckr_hostnames_set_ctx_set("test-names", hostnames);
    vp = get_dnsf_ckr_victims_ctx_victim("penelope", victims);
    CUTE_CHECK("fp->victim != penelope", fp->with == vp);
    CUTE_CHECK("fp->mess_up != google-names", fp->mess_up == hp);

    fp = fp->next;

    CUTE_CHECK("fp == NULL", fp != NULL);
    hp = get_dnsf_ckr_hostnames_set_ctx_set("local-names", hostnames);
    vp = get_dnsf_ckr_victims_ctx_victim("work-machine", victims);
    CUTE_CHECK("fp->victim != work-machine", fp->with == vp);
    CUTE_CHECK("fp->mess_up != local-names", fp->mess_up == hp);

    fp = fp->next;

    CUTE_CHECK("fp == NULL", fp != NULL);
    hp = get_dnsf_ckr_hostnames_set_ctx_set("test-names", hostnames);
    vp = get_dnsf_ckr_victims_ctx_victim("old-work-machine", victims);
    CUTE_CHECK("fp->victim != old-work-machine", fp->with == vp);
    CUTE_CHECK("fp->mess_up != google-names", fp->mess_up == hp);

    hp = get_dnsf_ckr_hostnames_set_ctx_set("local-names", hostnames);
    CUTE_CHECK("fp->mess_up->next == NULL", fp->mess_up != NULL);
    CUTE_CHECK("fp->mess_up->next != local-names", fp->mess_up->next == hp);

    del_dnsf_ckr_victims_ctx(victims);
    del_dnsf_ckr_hostnames_set_ctx(hostnames);
    del_dnsf_ckr_fakenameserver_ctx(fakenameserver);

    fclose(config);
    remove("dnsf_ckr-test.conf");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_config_parsing_realdnstransactions_test)
    const char *config_data = "dns-servers = \n"
                              "\ttest-dns : 192.168.7.15\n"
                              ";"
                              "victims = \n"
                              "\tloopback\t\t\t\t\t\t\t:127.0.0.1;\n"
                              "real-dns-transactions = \n"
                              "loopback sends requests to test-dns\n;";
    FILE *config = NULL;
    dnsf_ckr_victims_ctx *victims = NULL;
    dnsf_ckr_servers_ctx *servers = NULL;
    dnsf_ckr_realdnstransactions_ctx *transactions = NULL;
    CUTE_CHECK("Unable to write to \"dnsf_ckr-test.conf\"",
                write_buffer_to_file(config_data,
                                     strlen(config_data),
                                     "dnsf_ckr-test.conf") == 1);
    config = fopen("dnsf_ckr-test.conf", "rb");
    victims = dnsf_ckr_get_victims_config(config);
    CUTE_CHECK("victims == NULL", victims != NULL);
    servers = dnsf_ckr_get_servers_config(config);
    CUTE_CHECK("servers == NULL", servers != NULL);
    transactions = dnsf_ckr_get_realdnstransactions_config(config, victims, servers);
    CUTE_CHECK("transactions == NULL", transactions != NULL);
    CUTE_CHECK("transactions->victim != victims", transactions->victim == victims);
    CUTE_CHECK("transactions->sends_reqs_to != servers", transactions->sends_reqs_to == servers);
    del_dnsf_ckr_victims_ctx(victims);
    del_dnsf_ckr_servers_ctx(servers);
    del_dnsf_ckr_realdnstransactions_ctx(transactions);
    remove("dnsf_ckr-test.conf");
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_config_parsing_intvalues_reading_test)
    const char *data = "dnsf_ckr-core =\n\tintvalue:101\n\tx:0\n\ty:1\n\tz:2\n;\n";
    FILE *config = NULL;
    CUTE_CHECK("Unable to write to \"dnsf_ckr-test.conf\"",
                write_buffer_to_file(data,
                                     strlen(data),
                                     "dnsf_ckr-test.conf") == 1);
    config = fopen("dnsf_ckr-test.conf", "rb");
    CUTE_CHECK("config == NULL", config != NULL);
    remove("dnsf_ckr-test.conf");
    CUTE_CHECK("wrong intvalue [expected:101]", dnsf_ckr_get_core_int_config(config, "intvalue", 99) == 101);
    CUTE_CHECK("wrong x [expected:0]", dnsf_ckr_get_core_int_config(config, "x", 99) == 0);
    CUTE_CHECK("wrong y [expected:1]", dnsf_ckr_get_core_int_config(config, "y", 99) == 1);
    CUTE_CHECK("wrong z [expected:2]", dnsf_ckr_get_core_int_config(config, "z", 99) == 2);
    CUTE_CHECK("wrong z_ [expected:99]", dnsf_ckr_get_core_int_config(config, "z_", 99) == 99);
    fclose(config);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_config_parsing_gateways_config_test)
    const char *data = "dns-servers =\n"
                       "\tfoo: 192.30.70.15\n"
                       "\tbar: 192.30.70.16\n"
                       ";\n\n"
                       "victims = \n"
                       "\talice: 127.0.0.1\n"
                       "\tbob: 127.0.0.2\n"
                       ";\n\n"
                       "gateways-config =\n"
                       "\talice gateway foo\n"
                       "\tbob gateway bar\n"
                       ";\n\n";
    FILE *config = NULL;
    dnsf_ckr_servers_ctx *servers = NULL;
    dnsf_ckr_victims_ctx *victims = NULL;
    dnsf_ckr_gateways_config_ctx *gateways_cfg = NULL;
    CUTE_CHECK("Unable to write to \"dnsf_ckr-test.conf\"",
                     write_buffer_to_file(data, strlen(data), "dnsf_ckr-test.conf") == 1);
    config = fopen("dnsf_ckr-test.conf", "rb");
    CUTE_CHECK("config == NULL", config != NULL);
    remove("dnsf_ckr-test.conf");
    victims = dnsf_ckr_get_victims_config(config);
    CUTE_CHECK("victims == NULL", victims != NULL);
    servers = dnsf_ckr_get_servers_config(config);
    CUTE_CHECK("servers == NULL", servers != NULL);
    gateways_cfg = dnsf_ckr_get_gatewaysconfig_config(config, victims, servers);
    CUTE_CHECK("gateways_cfg == NULL", gateways_cfg != NULL);
    fclose(config);
    CUTE_CHECK("gateways_cfg->victim != victims", gateways_cfg->victim == victims);
    CUTE_CHECK("gateways_cfg->server != servers", gateways_cfg->server == servers);
    CUTE_CHECK("gateways_cfg->next == NULL", gateways_cfg->next != NULL);
    CUTE_CHECK("gateways_cfg->next->victim != victims", gateways_cfg->next->victim == victims->next);
    CUTE_CHECK("gateways_cfg->next->server != servers", gateways_cfg->next->server == servers->next);
    del_dnsf_ckr_victims_ctx(victims);
    del_dnsf_ckr_servers_ctx(servers);
    del_dnsf_ckr_gateways_config_ctx(gateways_cfg);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_config_parsing_tests)
    CUTE_RUN_TEST(dnsf_ckr_config_parsing_victims_test);
    CUTE_RUN_TEST(dnsf_ckr_config_parsing_servers_test);
    CUTE_RUN_TEST(dnsf_ckr_config_parsing_hostnames_test);
    CUTE_RUN_TEST(dnsf_ckr_config_parsing_fakenameserver_test);
    CUTE_RUN_TEST(dnsf_ckr_config_parsing_realdnstransactions_test);
    CUTE_RUN_TEST(dnsf_ckr_config_parsing_intvalues_reading_test);
    CUTE_RUN_TEST(dnsf_ckr_config_parsing_gateways_config_test);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_dnsresolvcache_ctx_tests)
    dnsf_ckr_dnsresolvcache_ctx *resolv = NULL, *rp;
    struct resolutions_cache {
        char *dname;
        size_t dname_size;
        unsigned char *reply;
        size_t reply_size;
    };
    static char message[1024];
    static struct resolutions_cache resolutions_cache_data[6] = {
        {"penelope-charmosa",  17, "REP_0", 5},
        {"dick-vigarista",     14, "REP_1", 5},
        {"quadrilha-de-morte", 18, "REP_2", 5},
        {"barao-vermelho",     14, "REP_3", 5},
        {"irmaos-pedregulho",  17, "REP_4", 5},
        {"muttley",             7, "REP_5", 5}
    };
    int r;
    //  basic push tests.
    for (r = 0; r < 6; r++) {
        resolv = push_resolution_to_dnsf_ckr_dnsresolvcache_ctx(&resolv, 100,
                                                                resolutions_cache_data[r].dname,
                                                                resolutions_cache_data[r].dname_size,
                                                                resolutions_cache_data[r].reply,
                                                                resolutions_cache_data[r].reply_size);
    }
    rp = resolv;
    for (r = 5; r > -1; r--, rp = rp->next) {
        CUTE_CHECK("rp == NULL", rp != NULL);
        sprintf(message, "%s != %s (expected: %s)", rp->dname, resolutions_cache_data[r].dname, resolutions_cache_data[r].dname);
        CUTE_CHECK(message, strcmp(rp->dname, resolutions_cache_data[r].dname) == 0);
        sprintf(message, "%d != %d (expected: %d)", rp->dname_size, resolutions_cache_data[r].dname_size, resolutions_cache_data[r].dname_size);
        CUTE_CHECK(message, rp->dname_size == resolutions_cache_data[r].dname_size);
        sprintf(message, "%s != %s (expected: %s)", rp->reply, resolutions_cache_data[r].reply, resolutions_cache_data[r].reply);
        CUTE_CHECK(message, strcmp(rp->reply, resolutions_cache_data[r].reply) == 0);
        sprintf(message, "%d != %d (expected: %d)", rp->reply_size, resolutions_cache_data[r].reply_size, resolutions_cache_data[r].reply_size);
        CUTE_CHECK(message, rp->reply_size == resolutions_cache_data[r].reply_size);
    }
    CUTE_CHECK("resolv not totally visited.", rp == NULL);
    del_dnsf_ckr_dnsresolvcache_ctx(resolv);
    //  cache limit test.
    resolv = NULL;
    for (r = 0; r < 6; r++) {
        resolv = push_resolution_to_dnsf_ckr_dnsresolvcache_ctx(&resolv, 4,
                                                                resolutions_cache_data[r].dname,
                                                                resolutions_cache_data[r].dname_size,
                                                                resolutions_cache_data[r].reply,
                                                                resolutions_cache_data[r].reply_size);
    }
    rp = resolv;
    for (r = 5; r > 1; r--, rp = rp->next) {
        CUTE_CHECK("rp == NULL", rp != NULL);
        sprintf(message, "%s != %s (expected: %s)", rp->dname, resolutions_cache_data[r].dname, resolutions_cache_data[r].dname);
        CUTE_CHECK(message, strcmp(rp->dname, resolutions_cache_data[r].dname) == 0);
        sprintf(message, "%d != %d (expected: %d)", rp->dname_size, resolutions_cache_data[r].dname_size, resolutions_cache_data[r].dname_size);
        CUTE_CHECK(message, rp->dname_size == resolutions_cache_data[r].dname_size);
        sprintf(message, "%s != %s (expected: %s)", rp->reply, resolutions_cache_data[r].reply, resolutions_cache_data[r].reply);
        CUTE_CHECK(message, strcmp(rp->reply, resolutions_cache_data[r].reply) == 0);
        sprintf(message, "%d != %d (expected: %d)", rp->reply_size, resolutions_cache_data[r].reply_size, resolutions_cache_data[r].reply_size);
        CUTE_CHECK(message, rp->reply_size == resolutions_cache_data[r].reply_size);
    }
    CUTE_CHECK("the dnsf_ckr_dnsresolvcache_ctx's cache scheme seems broken (rp != NULL).", rp == NULL);
    del_dnsf_ckr_dnsresolvcache_ctx(resolv);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(dnsf_ckr_gateways_config_ctx_tests)
    dnsf_ckr_servers_ctx *servers = NULL;
    dnsf_ckr_victims_ctx *victims = NULL;
    dnsf_ckr_gateways_config_ctx *gateways_cfg = NULL;
    victims = add_victim_to_dnsf_ckr_victims_ctx(victims, "foo", 3, "127.0.0.1", 9);
    victims = add_victim_to_dnsf_ckr_victims_ctx(victims, "yyz", 3, "127.0.0.3", 9);
    servers = add_server_to_dnsf_ckr_servers_ctx(servers, "bar", 3, "127.0.0.2", 9);
    servers = add_server_to_dnsf_ckr_servers_ctx(servers, "baz", 3, "127.0.0.4", 9);
    gateways_cfg = add_config_to_dnsf_ckr_gateways_config_ctx(gateways_cfg, victims, servers);
    gateways_cfg = add_config_to_dnsf_ckr_gateways_config_ctx(gateways_cfg, victims->next, servers->next);
    CUTE_CHECK("gateways_cfg == NULL", gateways_cfg != NULL);
    CUTE_CHECK("gateways_cfg->victim != victims", gateways_cfg->victim == victims);
    CUTE_CHECK("gateways_cfg->server != servers", gateways_cfg->server == servers);
    CUTE_CHECK("gateways_cfg->next == NULL", gateways_cfg->next != NULL);
    CUTE_CHECK("gateways_cfg->next->victim != victims->next", gateways_cfg->next->victim == victims->next);
    CUTE_CHECK("gateways_cfg->next->server != servers->next", gateways_cfg->next->server == servers->next);
    del_dnsf_ckr_servers_ctx(servers);
    del_dnsf_ckr_victims_ctx(victims);
    del_dnsf_ckr_gateways_config_ctx(gateways_cfg);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(run_tests)
    printf("running unit tests...\n\n");
    CUTE_RUN_TEST(dnsf_ckr_victims_ctx_tests);
    CUTE_RUN_TEST(dnsf_ckr_servers_ctx_tests);
    CUTE_RUN_TEST(dnsf_ckr_hostnames_ctx_tests);
    CUTE_RUN_TEST(dnsf_ckr_hostnames_set_ctx_tests);
    CUTE_RUN_TEST(dnsf_ckr_fakenameserver_ctx_tests);
    CUTE_RUN_TEST(dnsf_ckr_realdnstransactions_ctx_tests);
    CUTE_RUN_TEST(dnsf_ckr_dnsresolvcache_ctx_tests);
    CUTE_RUN_TEST(dnsf_ckr_gateways_config_ctx_tests);
    CUTE_RUN_TEST(dnsf_ckr_ip2num_test);
    CUTE_RUN_TEST(dnsf_ckr_is_valid_ipv4_test);
    CUTE_RUN_TEST(dnsf_ckr_ethernet_buffer_parsing_test);
    CUTE_RUN_TEST(dnsf_ckr_arp_buffer_parsing_test);
    CUTE_RUN_TEST(dnsf_ckr_ip_buffer_parsing_test);
    CUTE_RUN_TEST(dnsf_ckr_udp_buffer_parsing_test);
    CUTE_RUN_TEST(dnsf_ckr_chsum_basic_computing_test);
    CUTE_RUN_TEST(dnsf_ckr_udp_chsum_computing_test);
    CUTE_RUN_TEST(dnsf_ckr_config_parsing_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(run_tests)
