#include "watchdogs.h"
#include <pthread.h>

static int _should_abort = 0;

static pthread_mutex_t abrt_watchdog_mtx = PTHREAD_MUTEX_INITIALIZER;

int dnsf_ckr_should_abort() {
    int should = 0;
    pthread_mutex_lock(&abrt_watchdog_mtx);
    should = _should_abort;
    pthread_mutex_unlock(&abrt_watchdog_mtx);
    return should;
}

void dnsf_ckr_request_abort() {
    pthread_mutex_lock(&abrt_watchdog_mtx);
    _should_abort = 1;
    pthread_mutex_unlock(&abrt_watchdog_mtx);
}
