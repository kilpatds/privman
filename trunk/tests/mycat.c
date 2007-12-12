/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * mycat.c
 * This program opens the files specified, and  outputs them on standard
 * out.  Its is far more complex than it needs to be (fork?  Please.) in
 * order to test additional Privman functionality.
 *
 * $Id: mycat.c,v 1.8 2002/11/01 16:22:27 dougk Exp $
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
    int fd, i, n;
    char buf[4096];
    char *cwd;

    if ((cwd = getcwd(0,1024)) == NULL) /* priv_init does a chdir("/") */
        perror("getcwd");

    priv_init("mycat");

    if (chdir(cwd) < 0)
        perror("main(chdir)");

    for (i=1; i < argc; ++i) {
        pid_t   child;

        fd = priv_open(argv[i],O_RDONLY);
        if (fd < 0) {
            perror("priv_open");
            exit(-1);
        }
        child = priv_fork();
        if (child == 0) {
            while ( ( n = read(fd, buf, sizeof(buf))) > 0) {
                write(STDOUT_FILENO,buf,n);
            }
            close(fd);
            _exit(0);
        } else if (child > 0) {
            close(fd);
            if ( (n = waitpid(child, 0, 0)) < 0)
                perror("waitpid(main)");
        } else {
            perror("priv_fork");
            exit(-1);
        }
    }

    exit(0);
}
