#ifndef _DNSF_CKR_UTEST_H
#define _DNSF_CKR_UTEST_H 1

#define UTEST_CHECK(msg, chk) do { if ((chk) == 0) { printf("hmm bad, bad bug in %s at line %d: ", __FILE__, __LINE__); return msg; } } while (0)

#define UTEST_RUN(test) do { char *msg = test();\
                             utest_ran_tests++;\
                             if (msg != NULL) return msg; } while (0)
extern int utest_ran_tests;

#endif
