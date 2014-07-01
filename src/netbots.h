#ifndef _DNSF_CKR_NETBOTS_H
#define _DNSF_CKR_NETBOTS_H 1

#define DNSF_CKR_BOT_ROUTINE_ARGS_NR 10

struct dnsf_ckr_bot_routine_ctx {
    void *arg[DNSF_CKR_BOT_ROUTINE_ARGS_NR];
};

void *dnsf_ckr_arp_spoofing_bot_routine(void *vargs);
void *dnsf_ckr_fakeserver_bot_routine(void *vargs);

#endif
