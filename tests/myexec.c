/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * myexec.c
 * This program executes "id" as user "joe".  Its simply a small test
 * program for priv_execve.
 *
 * $Id: myexec.c,v 1.6 2002/11/01 05:39:58 dougk Exp $
 */

#include "../config.h"

#define ID_PATH "/usr/bin/id"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#include "privman.h"

extern char **environ;

int main(void)
{
    char *argv[2] = { "id", 0 };
    struct passwd *pw;

    priv_init("myexec");

    priv_execve(ID_PATH, argv, environ, "root", 0);
    perror("priv_execve (should fail)");

    pw = getpwent();
    while (pw != NULL && pw->pw_uid < 10)
        pw = getpwent();

    priv_execve(ID_PATH, argv, environ, pw->pw_name, 0);

    perror("priv_execve(should not have failed)");

    return -1;
}
