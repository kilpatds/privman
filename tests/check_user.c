/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * check_user.c
 * This is a simplification and modification of the "check_user" program
 * contributed to PAM by Shane Watts.
 *
 * For privman test purposes, its uses the "login" pam stack instead
 * of its own.
 *
 * $Id: check_user.c,v 1.9 2002/11/12 23:26:27 dougk Exp $
 */

#include "../config.h"

#include "privman.h"

#include <stdio.h>
#if   defined(HAVE_SECURITY_PAM_MISC_H)
#include <security/pam_misc.h>
#elif defined(HAVE_PAM_PAM_MISC_H)
#include <pam/pam_misc.h>
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

static struct pam_conv conv = {
    misc_conv,
    NULL
};

void rerunfn(char * const args[])
{
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL)
        fprintf(stdout, "rerun as %s(%d)\n", pw->pw_name, pw->pw_uid);
    else
        fprintf(stdout, "rerun as %d\n", getuid());
    exit(0);
}

int main(int argc, char *argv[])
{
    pam_handle_t *pamh=NULL;
    int retval;
    const char *user="nobody";

    priv_init("check_user");

    if(argc == 2) {
        user = argv[1];
    }

    if(argc > 2) {
        fprintf(stderr, "Usage: check_user [username]\n");
        exit(1);
    }

    /* Use "login" cause I don't feel like copying check_user to pam.d */
    retval = priv_pam_start("login", user, &conv, &pamh);

    if (retval != PAM_SUCCESS) {
        fprintf(stdout, "pam_start failed.\n");
        goto finished;
    }
        
    retval = priv_pam_authenticate(pamh, 0); /* is user really user? */
    if (retval != PAM_SUCCESS) {
        fprintf(stdout, "Not Authenticated!\npam_authenticate failed.\n");
        goto finished;
    }

    retval = priv_pam_acct_mgmt(pamh, 0);    /* permitted access? */
    if (retval != PAM_SUCCESS) {
        fprintf(stdout, "pam_acct_mgmt failed.\n");
        goto finished;
    } else {
        fprintf(stdout, "Authenticated\n");
    }

finished:
    if (priv_pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
        pamh = NULL;
        fprintf(stderr, "check_user: failed to release authenticator\n");
        exit(1);
    }

    if (retval == PAM_SUCCESS) {
        retval = priv_rerunas(rerunfn, 0, user, NULL, 0);
        if (retval < 0)
            perror("priv_rerunas");
        _exit(0);
    } else {
        return 1;
    }
}
