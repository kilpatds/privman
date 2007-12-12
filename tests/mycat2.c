/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * mycat2.c
 * This program opens the files specified, and  outputs them on standard
 * out.  Its is far more complex than it needs to be (fork?  Please.) in
 * order to test additional Privman functionality.
 *
 * $Id: mycat2.c,v 1.5 2002/11/01 16:22:27 dougk Exp $
 */

#include "../config.h"

#include "privman.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
    int i, n;
    char buf[4096];
    char *cwd;

    if ((cwd = getcwd(0,1024)) == NULL) /* priv_init does a chdir("/") */
        perror("getcwd");

    /* Reuse the one config file */
    priv_init("mycat");

    if (chdir(cwd) < 0)
        perror("main(chdir)");

    for (i=1; i < argc; ++i) {
        pid_t   child;
        FILE   *f;

        f = priv_fopen(argv[i], "r");
        if (f == NULL) {
            perror("priv_open");
            exit(-1);
        }
        child = priv_fork();
        if (child == 0) {
            while ( ( n = fread(buf, sizeof(*buf), sizeof(buf), f)) > 0) {
                write(STDOUT_FILENO,buf,n);
            }
            fclose(f);
            _exit(0);
        } else if (child > 0) {
            fclose(f);
            if ( (n = waitpid(child, 0, 0)) < 0)
                perror("waitpid(main)");
        } else {
            perror("priv_fork");
            exit(-1);
        }
    }

    exit(0);
}
