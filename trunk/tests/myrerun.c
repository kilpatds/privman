/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * myrerun.c
 * This program uses priv_rerun to print 0 through 5.  Each execution
 * should be as a different user (mail, news, ftp, rpc, nobody).  This
 * program should help demonstrate the use of priv_rerunas(), a less
 * than-obvious Privman method.
 *
 * $Id: myrerun.c,v 1.7 2002/11/01 05:39:58 dougk Exp $
 */

#include "../config.h"

#include "privman.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pwd.h>

/* Needs to be global so that rerun_fn and main can both see it. */
int state = 0;

void rerun_fn(char * const args[])
{
    /* This function will run before we drop out of priv_init the second
     * through fifth times.  Futz with global state so we can recognize
     * the situation.  args comes from the priv_rerunas call, and is a 
     * null-terminated array of strings.  Don't try and pass pointers via
     * args, it won't work.
     */
    state = atoi(args[0]);
}

int main(void) {
    const char *users[5];
    struct passwd *pw;
    int i = 0;

    while (i < 5 && (pw = getpwent()) != NULL) {
        if (pw->pw_uid > 10) {
	    users[i++] = strdup(pw->pw_name);
	}
    } 
    /* Do this before priv_init so that children can see it. */
    
    priv_init("myrerun");

    /* Nothing up my sleeve... */
    pw = getpwuid(getuid());
    printf("state = %d, uid = %d/%d (%s)\n", state,
		    getuid(), geteuid(), pw->pw_name);
    if (state < 5) {
        char **arg;
        arg = (char**)malloc(sizeof(char *) * 2);
        arg[0] = malloc(5);
        arg[1] = 0;
        /* Create a string to pass the state to the next iteration. */
        snprintf(arg[0], 4, "%d", state + 1);

        /* setuid to user, don't chroot, call rerun_fn(arg) before dropping
         * out of priv_init again.
         */
        if ( priv_rerunas(rerun_fn, arg, users[state], NULL, 0) < 0)
            fprintf(stderr,"priv_rerunas failed.\n");
        _exit(0);
    }

    exit(EXIT_SUCCESS);
}

