#include "conf.h"
#include "ctxs.h"
#include "iputils.h"
#include <stdio.h>
#include <string.h>

#define DNSF_CKR_MAX_BUF        8192

#define dnsf_ckr_is_blank(b) ( (b) == ' ' || (b) == '\t' || (b) == '\r' || (b) == '\n' )

#define dnsf_ckr_is_ftoken(t) ( (t) == '=' ||\
                                (t) == ':' ||\
                                (t) == ';' ||\
                                dnsf_ckr_is_blank(t) )

#define dnsf_ckr_is_comment(c) ( (c) == '#' )

static char dnsf_ckr_skip_blank(FILE *conf);

static void dnsf_ckr_get_next_word_from_config(char *buf, size_t bufsize, FILE *conf) {
    size_t b;
    char c;
    if (buf == NULL) return;
    memset(buf, 0, bufsize);
    if (feof(conf)) return;
    b = 0;
    while (b == 0 && !feof(conf)) {
        c = fgetc(conf);
        while (!feof(conf) && (!dnsf_ckr_is_ftoken(c) && b < bufsize)) {
            if (dnsf_ckr_is_comment(c)) {
                while (c != '\n') {
                    c = fgetc(conf);
                }
            } else {
                buf[b++] = c;
            }
            c = fgetc(conf);
        }
    }
    if (b > 0) fseek(conf, ftell(conf) - 1, SEEK_SET);
}

void dnsf_ckr_get_next_line_from_config(char *buf, size_t bufsize, FILE *conf) {
    char c;
    size_t b = 0;
    if (buf == NULL) return;
    memset(buf, 0, bufsize);
    if (feof(conf)) return;
    c = dnsf_ckr_skip_blank(conf);
    while (!feof(conf) && b < bufsize && (c != '\n' && c != '\r')) {
        buf[b++] = c;
        c = fgetc(conf);
    }
    if (b > 0) fseek(conf, ftell(conf) - 1, SEEK_SET);
}

static char dnsf_ckr_skip_blank(FILE *conf) {
    char c = fgetc(conf);
    while (dnsf_ckr_is_blank(c)) c = fgetc(conf);
    return c;
}

static long dnsf_ckr_get_config_section_end(FILE *conf) {
    long old_offset = ftell(conf);
    long end_offset = -1;
    char c = fgetc(conf);
    while (!feof(conf)) {
        if (c == '\\') {
            c = fgetc(conf);
            c = fgetc(conf);
        }
        if (c == ';') {
            end_offset = ftell(conf) - 1;
            break;
        }
        c = fgetc(conf);
    }
    fseek(conf, old_offset, SEEK_SET);
    return end_offset;
}

int dnsf_ckr_find_config_section(const char *sec, FILE *conf, long *cfg_end) {
    long seek_start = 0;
    char c;
    char buf[DNSF_CKR_MAX_BUF];
    if (conf == NULL || cfg_end == NULL) {
        return 0;
    }
    *cfg_end = -1;
    while (!feof(conf) && *cfg_end == -1) {
        dnsf_ckr_get_next_word_from_config(buf, sizeof(buf), conf);
        if (buf[0] == 0) break;
        c = fgetc(conf);
        if (strcmp(sec, buf) == 0) {
            c = dnsf_ckr_skip_blank(conf);
            seek_start = ftell(conf);
            *cfg_end = dnsf_ckr_get_config_section_end(conf);
            fseek(conf, seek_start - 1, SEEK_SET);
        } else {
            fseek(conf, ftell(conf) - 1, SEEK_SET);
        }
    }
    return (*cfg_end != -1);
}

dnsf_ckr_victims_ctx *dnsf_ckr_get_victims_config(FILE *conf) {
    long cfg_end;
    char cfgline[DNSF_CKR_MAX_BUF], name[DNSF_CKR_MAX_BUF], addr[DNSF_CKR_MAX_BUF];
    size_t l, add_count = 0;
    char c;
    dnsf_ckr_victims_ctx *victims = NULL;
    if (dnsf_ckr_find_config_section("victims", conf, &cfg_end)) {
        while (ftell(conf) < cfg_end) {
            c = dnsf_ckr_skip_blank(conf);
            l = 0;
            if (add_count == 0 && c != '=') {
                del_dnsf_ckr_victims_ctx(victims);
                return NULL;
            } else if (add_count == 0 && c == '=') {
                c = dnsf_ckr_skip_blank(conf);
            }
            memset(cfgline, 0, sizeof(cfgline));
            while (ftell(conf) < cfg_end && c != '\n' && l < sizeof(cfgline)) {
                cfgline[l++] = c;
                c = fgetc(conf);
            }
            l = 0;
            memset(name, 0, sizeof(name));
            for (l = 0; cfgline[l] != ':' && cfgline[l] != 0; l++);
            if (cfgline[l] == 0) {
                del_dnsf_ckr_victims_ctx(victims);
                return NULL;
            }
            memcpy(name, cfgline, l);
            for (l++;dnsf_ckr_is_blank(cfgline[l]); l++);
            memset(addr, 0, sizeof(addr));
            strncpy(addr, &cfgline[l], sizeof(addr) - 1);
            victims = add_victim_to_dnsf_ckr_victims_ctx(victims, name, strlen(name), addr, strlen(addr));
            add_count += 1;
        }
    }
    return victims;
}

dnsf_ckr_servers_ctx *dnsf_ckr_get_servers_config(FILE *conf) {
    long cfg_end;
    char addr[DNSF_CKR_MAX_BUF], name[DNSF_CKR_MAX_BUF], c;
    size_t l;
    dnsf_ckr_servers_ctx *servers = NULL;
    fseek(conf, 0L, SEEK_SET);
    while (dnsf_ckr_find_config_section("dns-servers", conf, &cfg_end)) {
        c = dnsf_ckr_skip_blank(conf);
        if (c != '=') continue;
        c = dnsf_ckr_skip_blank(conf);
        l = 0;
        memset(name, 0, sizeof(name));
        while (ftell(conf) < cfg_end && !dnsf_ckr_is_blank(c) && c != ':' && l < sizeof(name)) {
            name[l++] = c;
            c = fgetc(conf);
        }
        c = fgetc(conf);
        if (dnsf_ckr_is_blank(c)) {
            c = dnsf_ckr_skip_blank(conf);
        }
        memset(addr, 0, sizeof(addr));
        l = 0;
        while (ftell(conf) < cfg_end && !dnsf_ckr_is_blank(c) && l < sizeof(addr)) {
            addr[l++] = c;
            c = fgetc(conf);
        }
        if (!dnsf_ckr_is_valid_ipv4(addr)) {
            printf("dnsf_ckr error: server has an invalid ipv4 address \"%s\"\n", addr);
            del_dnsf_ckr_servers_ctx(servers);
            return NULL;
        }
        servers = add_server_to_dnsf_ckr_servers_ctx(servers, name, strlen(name), addr, strlen(addr));
        fseek(conf, cfg_end, SEEK_SET);
    }
    return servers;
}

static dnsf_ckr_hostnames_ctx *dnsf_ckr_parse_addrname_decl(dnsf_ckr_hostnames_ctx *hostnames, const char *addrname) {
    char data[2][DNSF_CKR_MAX_BUF];
    const char *a;
    size_t d, i;
    i = 0;
    d = 0;
    for (a = addrname; *a != 0; a++) {
        if ((*a == ':' || dnsf_ckr_is_blank(*a) || *(a+1) == 0) && i > 0) {
            if (*(a+1) == 0) data[d][i++] = *a;
            while (i > 0 && dnsf_ckr_is_blank(data[d][i-1])) {
                i--;
                data[d][i] = 0;
            }
            data[d][i] = 0;
            if (d == 1) {
                hostnames = add_host_to_dnsf_ckr_hostnames_ctx(hostnames, data[0], strlen(data[0]), data[1], strlen(data[1]));
            }
            d++;
            i = 0;
            if (dnsf_ckr_is_blank(*a)) {
                while (dnsf_ckr_is_blank(*a)) a++;
                a--;
            }

        } else {
            if (i == 0 && dnsf_ckr_is_blank(*a)) while (dnsf_ckr_is_blank(*a)) a++;
            data[d][i++] = *a;
        }
    }
    return hostnames;
}

dnsf_ckr_hostnames_set_ctx *dnsf_ckr_get_hostnames_config(FILE *conf) {
    long cfg_end;
    char cfgbuf[DNSF_CKR_MAX_BUF], c;
    size_t l;
    dnsf_ckr_hostnames_set_ctx *hset = NULL, *hset_tail;
    fseek(conf, 0L, SEEK_SET);
    while (dnsf_ckr_find_config_section("namelist", conf, &cfg_end)) {
        c = dnsf_ckr_skip_blank(conf);
        l = 0;
        memset(cfgbuf, 0, sizeof(cfgbuf));
        while (ftell(conf) < cfg_end && !dnsf_ckr_is_blank(c) && l < sizeof(cfgbuf)) {
            cfgbuf[l++] = c;
            c = fgetc(conf);
        }
        c = dnsf_ckr_skip_blank(conf);
        if (c == '=') {
            hset = add_set_to_dnsf_ckr_hostnames_set_ctx(hset, cfgbuf, strlen(cfgbuf));
            hset_tail = get_dnsf_ckr_hostnames_set_ctx_tail(hset);
            dnsf_ckr_get_next_line_from_config(cfgbuf, sizeof(cfgbuf), conf);
            while (ftell(conf) < cfg_end) {
                hset_tail->hostnames = dnsf_ckr_parse_addrname_decl(hset_tail->hostnames, cfgbuf);
                dnsf_ckr_get_next_line_from_config(cfgbuf, sizeof(cfgbuf), conf);
            }
        } else {
            del_dnsf_ckr_hostnames_set_ctx(hset);
            return NULL;
        }
    }
    return hset;
}

int dnsf_ckr_get_dnsproto_int_config(FILE *conf, const char *setting_name, const int default_value) {
    long cfg_end;
    int found;
    char c;
    char cur_setting[DNSF_CKR_MAX_BUF];
    fseek(conf, 0L, SEEK_SET);
    found = dnsf_ckr_find_config_section("dnsproto", conf, &cfg_end);
    if (found) {
        c = dnsf_ckr_skip_blank(conf);
        if (c == '=') {
            while (ftell(conf) < cfg_end) {
                dnsf_ckr_get_next_word_from_config(cur_setting, sizeof(cur_setting), conf);
                //printf("%s\n", cur_setting);
                if (strcmp(setting_name, cur_setting) == 0) {
                    c = dnsf_ckr_skip_blank(conf);
                    dnsf_ckr_get_next_word_from_config(cur_setting, sizeof(cur_setting), conf);
                    return atoi(cur_setting);
                } else {
                    c = fgetc(conf);
                    while (ftell(conf) < cfg_end && c != '\n') {
                        c = fgetc(conf);
                    }
                }
            }
        }
    }
    return default_value;
}

static int dnsf_ckr_parse_faking_decl(const char *faking_decl, dnsf_ckr_fakenameserver_ctx **nameserver, dnsf_ckr_victims_ctx *victims, dnsf_ckr_hostnames_set_ctx *hset) {
    const char *f = faking_decl;
    char buf[DNSF_CKR_MAX_BUF];
    const char *m = NULL;
    size_t b;
    dnsf_ckr_victims_ctx *vp;
    dnsf_ckr_hostnames_set_ctx *hp;
    f = strstr(faking_decl, "with");
    if (f != faking_decl) {
        printf("dnsf_ckr ERROR: expecting \"with\" on a faking declaration\n");
        del_dnsf_ckr_fakenameserver_ctx(*nameserver);
        return 0;
    }
    f += strlen("with");
    while (dnsf_ckr_is_blank(*f)) f++; // going to position after "with "
    b = 0;
    memset(buf, 0, sizeof(buf));
    while (!dnsf_ckr_is_blank(*f) && b < sizeof(buf)) { // parsing the victim name
        buf[b++] = *f;
        f++;
    }
    if ((vp = get_dnsf_ckr_victims_ctx_victim(buf, victims)) == NULL) {
        printf("dnsf_ckr ERROR: unknown victim : \"%s\"\n", buf);
        del_dnsf_ckr_fakenameserver_ctx(*nameserver);
        return 0;
    }
    while (dnsf_ckr_is_blank(*f)) {
        f++;
    }
    m = strstr(faking_decl, "mess up");
    if (f != m) {
        printf("dnsf_ckr ERROR: expecting \"mess up\" on a faking declaration\n");
        del_dnsf_ckr_fakenameserver_ctx(*nameserver);
        return 0;
    }
    f += strlen("mess up");
    for (; *f != 0; f++) {
        memset(buf, 0, sizeof(buf));
        b = 0;
        while (dnsf_ckr_is_blank(*f)) {
            f++;
        }
        while (*f != ',' && *f != 0 && b < sizeof(buf)) {
            buf[b++] = *f;
            f++;
        }
        hp = get_dnsf_ckr_hostnames_set_ctx_set(buf, hset);
        if (hp == NULL) {
            printf("dnsf_ckr ERROR: unknown namelist : \"%s\"\n", buf);
            del_dnsf_ckr_fakenameserver_ctx(*nameserver);
            return 0;
        }
        *nameserver = add_faking_to_dnsf_ckr_fakenameserver_ctx(*nameserver, vp, hp);
    }
    return 1;
}

dnsf_ckr_fakenameserver_ctx *dnsf_ckr_get_fakenameserver_config(FILE *conf, dnsf_ckr_victims_ctx *victims, dnsf_ckr_hostnames_set_ctx *hset) {
    dnsf_ckr_fakenameserver_ctx *nameserver = NULL;
    long cfg_end;
    int section_found = 0;
    char fkdecl[DNSF_CKR_MAX_BUF];
    char c;
    fseek(conf, 0L, SEEK_SET);
    while (!section_found && !feof(conf)) {
        section_found = dnsf_ckr_find_config_section("fake-nameserver", conf, &cfg_end);
        if (section_found) {
            c = dnsf_ckr_skip_blank(conf);
            if (c == '=') {
                while (ftell(conf) < cfg_end) {
                    dnsf_ckr_get_next_line_from_config(fkdecl, sizeof(fkdecl), conf);
                    if (dnsf_ckr_is_comment(fkdecl[0])) continue;
                    if (ftell(conf) < cfg_end) {
                        if (dnsf_ckr_parse_faking_decl(fkdecl, &nameserver, victims, hset) == 0) {
                            return NULL;
                        }
                    }
                }
            }
        }
    }
    return nameserver;
}

static int dnsf_ckr_parse_transactions_decl(const char *decl, dnsf_ckr_realdnstransactions_ctx **transactions, dnsf_ckr_victims_ctx *victims, dnsf_ckr_servers_ctx *servers) {
    const char *d = decl;
    char buf[DNSF_CKR_MAX_BUF];
    int s;
    dnsf_ckr_victims_ctx *victim;
    dnsf_ckr_servers_ctx *server;
    size_t b = 0;
    if (*decl == ';') return 1;
    memset(buf, 0, sizeof(buf));
    while (!dnsf_ckr_is_blank(*d) && *d != 0 && b < sizeof(buf)-1) {
        buf[b++] = *d;
        d++;
    }
    victim = get_dnsf_ckr_victims_ctx_victim(buf, victims);
    if (victim == NULL) {
        printf("dnsf_ckr ERROR: unknown victim : \"%s\"\n", buf);
        return 0;
    }
    for (s = 0; s < 3; s++) {
        while (*d != 0 && dnsf_ckr_is_blank(*d)) d++;
        b = 0;
        memset(buf, 0, sizeof(buf));
        while (!dnsf_ckr_is_blank(*d) && *d != 0 && b < sizeof(buf)-1) {
            buf[b++] = *d;
            d++;
        }
        d++;
        switch (s) {
            case 0:
                if (strcmp(buf, "sends") != 0) {
                    printf("dnsf_ckr ERROR: expecting \"sends requests to\" on a real dns transaction declaration.\n");
                    return 0;
                }
                break;
            case 1:
                if (strcmp(buf, "requests") != 0) {
                    printf("dnsf_ckr ERROR: expecting \"sends requests to\" on a real dns transaction declaration.\n");
                    return 0;
                }
                break;
            case 2:
                if (strcmp(buf, "to") != 0) {
                    printf("dnsf_ckr ERROR: expecting \"sends requests to\" on a real dns transaction declaration.\n");
                    return 0;
                }
                break;
        }
    }
    while (*d != 0 && dnsf_ckr_is_blank(*d)) d++;
    b = 0;
    memset(buf, 0, sizeof(buf));
    while (!dnsf_ckr_is_blank(*d) && *d != 0 && b < sizeof(buf)-1) {
        buf[b++] = *d;
        d++;
    }
    server = get_dnsf_ckr_servers_ctx_name(buf, servers);
    if (server == NULL) {
        printf("dnsf_ckr ERROR: unknown server : \"%s\"\n", buf);
        return 0;
    }
    *transactions = add_transaction_to_dnsf_ckr_realdnstransactions_ctx(*transactions, victim, server);
    return 1;
}

dnsf_ckr_realdnstransactions_ctx *dnsf_ckr_get_realdnstransactions_config(FILE *conf, dnsf_ckr_victims_ctx *victims, dnsf_ckr_servers_ctx *servers) {
    dnsf_ckr_realdnstransactions_ctx *transactions = NULL;
    long cfg_end;
    int section_found = 0;
    char trdecl[DNSF_CKR_MAX_BUF];
    char c;
    fseek(conf, 0L, SEEK_SET);
    while (!section_found && !feof(conf)) {
        section_found = dnsf_ckr_find_config_section("real-dns-transactions", conf, &cfg_end);
        if (section_found) {
            c = dnsf_ckr_skip_blank(conf);
            if (c == '=') {
                while (ftell(conf) < cfg_end) {
                    dnsf_ckr_get_next_line_from_config(trdecl, sizeof(trdecl), conf);
                    if (dnsf_ckr_is_comment(trdecl[0])) continue;
                    if (dnsf_ckr_parse_transactions_decl(trdecl, &transactions, victims, servers) == 0) {
                        del_dnsf_ckr_realdnstransactions_ctx(transactions);
                        return NULL;
                    }
                }
            }
        }
    }
    return transactions;
}

