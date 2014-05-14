#include "dnscore.h"
#include "conf.h"
#include <sys/types.h>

int main(int argc, char **argv) {
    FILE *fp = fopen("dnsf_ckr.conf", "rb");
    dnsf_ckr_victims_ctx *victims = dnsf_ckr_get_victims_config(fp), *v;
    dnsf_ckr_servers_ctx *servers = NULL, *s;
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
    fclose(fp);
    del_dnsf_ckr_fakenameserver_ctx(fakenameserver);
    del_dnsf_ckr_victims_ctx(victims);
    del_dnsf_ckr_hostnames_set_ctx(hostnames);
    return 0;
}
