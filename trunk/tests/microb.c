/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * microb.c
 * This is a benchmark program.  It tests the speed of various priv_
 * operations in comparison to their non-priv versions.
 *
 * $Id: microb.c,v 1.3 2003/03/08 05:41:46 dougk Exp $
 */

#define REP_COUNT 100000
#define TEST_USER "testuser"
#define TEST_PASSWD "password"

#include "../config.h"

#include "privman.h"

#include <stdio.h>

#if   defined(HAVE_SECURITY_PAM_MISC_H)
#include <security/pam_misc.h>
#elif defined(HAVE_PAM_PAM_MISC_H)
#include <pam/pam_misc.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#include <math.h>

#if   defined(HAVE_SECURITY_PAM_APPL_H)
#include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif

#define USEC_IN_SEC 1000000
int ticks_per_sec = 0;

#ifdef __cplusplus
#define UNUSED(p)
#else
#define UNUSED(p) p __attribute((unused))
#endif

double tv_sub(struct timeval *tv1, struct timeval *tv2)
{
    return (tv1->tv_sec  - tv2->tv_sec) +
           (tv1->tv_usec - tv2->tv_usec) / (double)USEC_IN_SEC;
}


//Run this when you are done collecting data
double std_dev(double accum, double squared_accum, long n)
{
    if(0==n){
        //You may want to do something else instead of return 0
        return 0.0;
    } else
        return sqrt((squared_accum - ((accum * accum )/(n)))/(n-1));
}

#define testop( op )                                                    \
do {                                                                    \
    gettimeofday(&before, NULL);                                        \
    op;                                                                 \
    gettimeofday(&after, NULL);                                         \
} while (0)

#define compare_help(op, accum, accum_sq, accum_count, reps)            \
do {                                                                    \
    int i;                                                              \
    double rep_time;                                                    \
    for( i = 0 ; i < reps ; ++i) {                                      \
        testop( op );                                                   \
        rep_time = tv_sub(&after,&before);                              \
        accum += rep_time;                                              \
        accum_sq += (rep_time * rep_time);                              \
        accum_count += 1;                                               \
    }                                                                   \
} while (0)

#define compare( op1, op2, op1string, op2string, reps)                  \
do {                                                                    \
    double op1_total = 0.0, op1_sq_tot = 0.0; long op1_n = 0;           \
    double op2_total = 0.0, op2_sq_tot = 0.0; long op2_n = 0;           \
                                                                        \
    compare_help( op1, op1_total, op1_sq_tot, op1_n, reps);             \
    compare_help( op2, op2_total, op2_sq_tot, op2_n, reps);             \
                                                                        \
    fprintf(stderr, "%s\t%g +- %g\t%g\t%g\t%ld\n", op1string,           \
            op1_total / op1_n, std_dev(op1_total, op1_sq_tot, op1_n),   \
            op1_total, op1_sq_tot, op1_n);                              \
    fprintf(stderr, "%s\t%g +- %g\t%g\t%g\t%ld\n", op2string,           \
            op2_total / op2_n, std_dev(op2_total, op2_sq_tot, op2_n),   \
            op2_total, op2_sq_tot, op2_n);                              \
    fprintf(stderr,                                                     \
            "The privman version of %s takes %d%% as long as the original\n",\
            op2string, (int)(op1_total * 100.0 / op2_total));            \
} while (0)

void rerunfn()
{
    exit(0);
}

/*
 * Function to test the speed of rerun.
 */
void test_rerun(void)
{
    pid_t pid;
    pid = priv_rerunas(rerunfn, NULL, "nobody", 0, PRIV_RR_OLD_SLAVE_MONITORED);
    priv_wait4(pid, 0, 0, 0);
}
void test_fork(void)
{
    pid_t pid;
    pid = fork();
    if (pid == 0)
        _exit(0);
    else
        wait4(pid,0,0,0);
}

static int cheat_convert(int n, const struct pam_message **msg,
        struct pam_response **resp, void *UNUSED(data))
{
    struct pam_response *reply = NULL;
    int i;

    reply = malloc(sizeof(*reply) * n);
    for ( i = 0; i < n; ++i ) {
        switch(msg[i]->msg_style) {
        default:
            fprintf(stderr, "Unknown style %d\n", msg[i]->msg_style);
            goto failed;
        case PAM_PROMPT_ECHO_ON:
            /* Username! */
            reply[i].resp_retcode = PAM_SUCCESS;
            reply[i].resp = strdup(TEST_USER);
            break;
        case PAM_PROMPT_ECHO_OFF:
            /* Password */
            reply[i].resp_retcode = PAM_SUCCESS;
            reply[i].resp = strdup(TEST_PASSWD);
            break;
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            reply[i].resp_retcode = PAM_SUCCESS;
            reply[i].resp = NULL;
            break;
        }
    }

    *resp = reply;
    return PAM_SUCCESS;
failed:
    free(reply);
    return PAM_CONV_ERR;
}

static struct pam_conv conv = {
    cheat_convert,
    NULL
};


void test_pam(void)
{
    pam_handle_t *pamh=NULL;
    int retval;

    /* Use "login" cause I don't feel like copying check_user to pam.d */
    retval = pam_start("login", NULL, &conv, &pamh);

    if (retval != PAM_SUCCESS)
        goto finished;
        
    retval = pam_authenticate(pamh, 0); /* is user really user? */
    if (retval != PAM_SUCCESS)
        goto finished;

    retval = pam_acct_mgmt(pamh, 0);    /* permitted access? */

finished:
    if (retval != PAM_SUCCESS)
        fprintf(stderr, "pam failed?\n");
    pam_end(pamh,retval);     /* close Linux-PAM */
}

void test_priv_pam(void)
{
    pam_handle_t *pamh=NULL;
    int retval;

    /* Use "login" cause I don't feel like copying check_user to pam.d */
    retval = priv_pam_start("login", NULL, &conv, &pamh);

    if (retval != PAM_SUCCESS)
        goto finished;
        
    retval = priv_pam_authenticate(pamh, 0); /* is user really user? */
    if (retval != PAM_SUCCESS)
        goto finished;

    retval = priv_pam_acct_mgmt(pamh, 0);    /* permitted access? */

finished:
    if (retval != PAM_SUCCESS)
        fprintf(stderr, "pam failed?\n");
    priv_pam_end(pamh,retval);     /* close Linux-PAM */
}

int main()
{
    struct timeval      before;
    struct timeval      after;
    struct sockaddr_in  addr;
    int                 fd;
    FILE               *f;
    double              pam_auth_time = 0.0, priv_pam_auth_time = 0.0;
    double              pam_auth_time_sq = 0.0, priv_pam_auth_time_sq = 0.0;
    long                pam_auth_time_n = 0, priv_pam_auth_time_n = 0;

    /* Init global constant */
    ticks_per_sec = sysconf(_SC_CLK_TCK);

    fprintf(stderr, "running benchmarks\n");
    /* Setup the libraries to take this out of the equation. */
    test_pam();
    /* Have to do this before priv_init */
    compare_help( test_pam(),
            pam_auth_time, pam_auth_time_sq, pam_auth_time_n,
            REP_COUNT / 10);

    /* Now priv_sep. */
    testop( priv_init("microb") );
    fprintf(stderr, "priv_init took 0.%6.6lu seconds\n",
            (long)(tv_sub(&after,&before) * USEC_IN_SEC));

    /* Test 0: pam_auth cycle. */

    compare_help( test_priv_pam(),
            priv_pam_auth_time, priv_pam_auth_time_sq, priv_pam_auth_time_n,
            REP_COUNT / 10);
    fprintf(stderr, "%s\t%g +- %g\t%g\t%g\t%ld\n", "pam_auth",
            pam_auth_time / pam_auth_time_n,
            std_dev(pam_auth_time, pam_auth_time_sq, pam_auth_time_n),
            pam_auth_time, pam_auth_time_sq, pam_auth_time_n);
    fprintf(stderr, "%s\t%g +- %g\t%g\t%g\t%ld\n", "priv_pam",
            priv_pam_auth_time / priv_pam_auth_time_n,
            std_dev(priv_pam_auth_time,
                priv_pam_auth_time_sq, priv_pam_auth_time_n),
            priv_pam_auth_time, priv_pam_auth_time_sq, priv_pam_auth_time_n);
    fprintf(stderr,
            "The privman version of %s takes %d%% as long as the original\n",
            "pam_authenticate",
            (int)(priv_pam_auth_time * 100.0 / pam_auth_time));

    /*
     * Test 1: open, fopen.
     */
    /* Cache the inodes. */
    fd = open("/etc/passwd", O_RDONLY); close(fd);

    compare( fd = priv_open("/etc/passwd", O_RDONLY); close(fd),
            fd = open("/etc/passwd", O_RDONLY); close(fd),
            "priv_open", "open    ", REP_COUNT);

    compare( f = priv_fopen("/etc/passwd", "r"); fclose(f),
             f = fopen("/etc/passwd", "r"); fclose(f),
             "priv_fopen", "fopen    ", REP_COUNT);

    addr.sin_family     = AF_INET;
    addr.sin_port       = htons(1234);
    addr.sin_addr.s_addr= INADDR_ANY;

    compare (
        fd = socket(PF_INET, SOCK_STREAM, 0);
        priv_bind(fd, (struct sockaddr *)&addr, sizeof(addr)); close(fd),
        fd = socket(PF_INET, SOCK_STREAM, 0);
        bind(fd, (struct sockaddr *)&addr, sizeof(addr)); close(fd),
        "priv_bind", "bind    ", REP_COUNT);

    compare (test_rerun(), test_fork(),
            "rerun    ", "fork+exit", REP_COUNT / 10);

    return 0;
}
