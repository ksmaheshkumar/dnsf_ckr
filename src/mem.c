/*
 *                              Copyright (C) 2014 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "mem.h"
#include <stdio.h>

void *dnsf_ckr_getmem(const size_t segsize) {
    void *mem = malloc(segsize);
    if (mem == NULL) {
        printf("dnsf_ckr PANIC: no memory!\n");
        exit(1);
    }
    return mem;
}

