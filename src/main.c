#include "dnscore.h"
#include "conf.h"
#include "types.h"
#include <sys/types.h>
#include "sk.h"
#include "arpspf.h"
#include "if.h"

int main(int argc, char **argv) {

    /*FILE *fp = fopen("dnsf_ckr.conf", "rb");
    dnsf_ckr_realdnstransactions_ctx *transactions = NULL, *tp;
    dnsf_ckr_victims_ctx *victims = dnsf_ckr_get_victims_config(fp), *v;
    dnsf_ckr_servers_ctx *servers = dnsf_ckr_get_servers_config(fp), *s;
    dnsf_ckr_hostnames_set_ctx *hostnames = NULL;
    dnsf_ckr_fakenameserver_ctx *fakenameserver = NULL, *fsp;
    for (v = victims; v; v = v->next) {
        printf("%s %s\n", v->name, inet_ntoa(v->addr));
    }
    fseek(fp, 0L, SEEK_SET);
    servers = dnsf_ckr_get_servers_config(fp);
    for (s = servers; s; s = s->next) {
        printf("server %s\n", inet_ntoa(s->addr));
    }
    hostnames = dnsf_ckr_get_hostnames_config(fp);

    printf("%d\n", dnsf_ckr_get_dnsproto_int_config(fp, "ttl-in-secs", 10));
    fakenameserver = dnsf_ckr_get_fakenameserver_config(fp, victims, hostnames);
    for (fsp = fakenameserver; fsp; fsp = fsp->next) {
        printf("with=%s mess up=%s\n", fsp->with->name, fsp->mess_up->name);
    }

    transactions = dnsf_ckr_get_realdnstransactions_config(fp, victims, servers);

    for (tp = transactions; tp != NULL; tp = tp->next) {
        printf("%s sends requests to %s\n", tp->victim->name, tp->sends_reqs_to->name);
    }

    fclose(fp);
    del_dnsf_ckr_fakenameserver_ctx(fakenameserver);
    del_dnsf_ckr_victims_ctx(victims);
    del_dnsf_ckr_hostnames_set_ctx(hostnames);
    del_dnsf_ckr_realdnstransactions_ctx(transactions);*/

    printf("MAC = %s\n", dnsf_ckr_get_iface_mac("em1"));
    printf("IP = %s\n", dnsf_ckr_get_iface_ip("em1"));
    /*dnsf_ckr_sk sk = dnsf_ckr_create_arp_socket("em1");
    if (sk != -1) {
        printf("created! :)\n");
        printf("arp spoof result = %d\n", dnsf_ckr_spoof_mac(sk, "08:00:27:f5:91:35",
                                                                 "192.30.70.171",
                                                                 "08:00:27:00:6C:74",
                                                                 "192.30.70.10", 60, 1));
    }*/
    return 0;
}
