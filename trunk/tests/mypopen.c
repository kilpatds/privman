/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * mypopen.c
 * This program uses priv_popen to run "id" as a different user.
 *
 * $Id: mypopen.c,v 1.3 2002/11/01 05:39:58 dougk Exp $
 */

#include "../config.h"

#include "privman.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>

int main(void) {
    FILE *stream;
    char buf[4096];
    struct passwd *pw;
    
    priv_init("mypopen");

    system("id");

    pw = getpwent();
    while (pw != NULL && pw->pw_uid < 10)
        pw = getpwent();

    if (pw == NULL) {
        fprintf(stderr, "no valid user to popen_as");
        return -1;
    }

    stream = priv_popen_as("id", "r", pw->pw_name);
    if (stream == NULL) {
        perror("priv_popen_as");
        return -1;
    }

    while ( fgets(buf, sizeof(buf), stream) ) {
        fprintf(stdout, ">> ");
        fprintf(stdout, buf);
    }
    priv_pclose(stream);

    return 0;
}
