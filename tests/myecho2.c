/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * myecho2.c
 * This program listens to port 7 (echo) and prints the output it gets
 * into the log file /var/log/myecho.log.  As it opens the log file itsself
 * (priv_fdreopen being difficult to write cross-platform) it won't work
 * properly if it doesn't have the correct permission.  It only listens
 * for one connection, and quits upon seeing ^D
 *
 * $Id: myecho2.c,v 1.8 2002/10/30 21:34:52 dougk Exp $
 */

#include "../config.h"

#include "privman.h"
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

#include <netdb.h>

/* ntohs */
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

int getPort(char *port) {
    /* port = "80"
     * port = "web"
     */
    char       *endptr;
    long        retval;

    retval = strtol(port, &endptr, 0);

    if (endptr == port) {
        /* no numbers in the string, so use getservbyname */
        struct servent *s = getservbyname(port, "tcp");
        if (s)
            retval = ntohs(s->s_port); /* comes in network order.  Gr. */
        else
            retval = 0;
    }

    if (retval < 0)
        return 0;

    if (retval > SHRT_MAX)
        return SHRT_MAX;

    return (int)retval;
}

int main(int argc, char *argv[])
{
    int sock, port, connection;
    int n;

    struct sockaddr_in  addr;
    struct sockaddr_in  client;
    int                 clientlen = sizeof(client);

    char                buf[4096];

    priv_init("myecho");

    freopen("/var/log/myecho.log", "a", stdout);
    freopen("/var/log/myecho.log", "a", stderr);

    if (priv_daemon(0,1) < 0) {
        perror("myecho2(daemon)");
        exit(EXIT_FAILURE);
    }

    if (argc < 2)
        port = getPort("echo");
    else
        port = getPort(argv[1]);

    if (port == 0) {
        fprintf(stderr,"Invalid port.\n");
        perror("myecho2");
        exit(EXIT_FAILURE);
    }

    sock = socket(PF_INET, SOCK_STREAM, 0); /* default protocol */
    if (sock < 0) {
        perror("myecho2(socket)");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    n = priv_bind(sock, (struct sockaddr *)(&addr), sizeof(addr));
    if (n < 0) {
        fprintf(stderr, "error binding to port %d\n", port);
        perror("myecho2(bind)");
        exit(EXIT_FAILURE);
    }
    fprintf(stdout,"listening on port %d as uid %d\n", port, geteuid());
    fflush(stdout);

    n = listen(sock, 0); /* Single connection */
    if (n < 0) {
        perror("myecho2(listen)");
        exit(EXIT_FAILURE);
    }

    connection = accept(sock, (struct sockaddr *)(&client), &clientlen);
    if (connection < 0) {
        perror("myecho2(accept)");
        exit(EXIT_FAILURE);
    }

    close(sock); /* single connection. */

    while ( ( n = read(connection,buf, sizeof(buf) ) ) > 0 ) {
        write(STDOUT_FILENO,buf,n);
        if (memchr(buf, 004, n) != NULL) /* 004 == EOT. End of Text. */
            break;
    }

    close(sock);

    exit(0);
}
