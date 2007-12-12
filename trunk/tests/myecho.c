/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * myechoc
 * This program listens to port 7 (echo), and also connects to port 7
 * from port 8.  It prints out anything that is sent through the
 * connection, which ought to be "test passed."  It only listens
 * for one connection, and quits upon seeing ^D
 *
 * $Id: myecho.c,v 1.15 2002/11/04 15:55:58 dougk Exp $
 */

#include "../config.h"

#include "privman.h"
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>

#include <netdb.h>

#include <errno.h>

#include <netinet/in.h>

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

int my_socket(char * const args[])
{
    static int handled = -1; /* Allow 2 calls. */
    int sock;
    if (handled < 1) {
        sock = socket(PF_INET, SOCK_STREAM, 0); /* default protocol */
        ++handled;
    } else {
        errno = EPERM;
        sock = -1;
    }
    return sock;
}

int main(int argc, char *argv[])
{
    int sock, port, connection;
    int sock2;
    int n, my_socket_handle;

    struct sockaddr_in  addr;
    struct sockaddr_in  client;
    struct sockaddr_in  server;
    int                 clientlen = sizeof(client);

    char                buf[4096];
    char * const        args[1] = { NULL }; 

    my_socket_handle = priv_register_cap_fn(my_socket);
    priv_init("myecho");

    if (argc < 2)
        port = getPort("echo");
    else
        port = getPort(argv[1]);

    if (port == 0) {
        printf("Invalid port.\n");
        perror("myecho");
        exit(EXIT_FAILURE);
    }

    sock = priv_invoke_cap_fn(my_socket_handle, args);
    if (sock < 0) {
        perror("myecho(socket)");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    n = priv_bind(sock, (struct sockaddr *)(&addr), sizeof(addr));
    if (n < 0) {
        perror("myecho(bind)");
        exit(EXIT_FAILURE);
    }
    printf("listening on port %d as uid %d\n", port, geteuid());
    fflush(stdout);

    n = listen(sock, 0); /* Single connection */
    if (n < 0) {
        perror("myecho(listen)");
        exit(EXIT_FAILURE);
    }

    /* server half.  For funzies. */
    sock2 = priv_invoke_cap_fn(my_socket_handle, args);
    if (sock2 < 0) {
        perror("myecho(socket 2)");
        exit(EXIT_FAILURE);
    }

    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port+1);

    n = priv_bind(sock2, (struct sockaddr *)(&server), sizeof(server));
    if (n < 0) {
        perror("myecho(bind 2)");
        exit(EXIT_FAILURE);
    }

    n = connect(sock2, (struct sockaddr *)(&addr), sizeof(addr));
    if (n < 0) {
        perror("myecho(connect)");
        exit(EXIT_FAILURE);
    }

    connection = accept(sock, (struct sockaddr *)(&client), &clientlen);
    if (connection < 0) {
        perror("myecho(accept)");
        exit(EXIT_FAILURE);
    }

    close(sock); /* single connection. */

    printf("received connection from port %d\n--\n", ntohs(client.sin_port));

    write(sock2, "test passed\n\004", 13);

    while ( ( n = read(connection,buf, sizeof(buf) ) ) > 0 ) {
        write(STDOUT_FILENO,buf,n);
        if (memchr(buf, 004, n) != NULL) /* 004 == EOT. End of Text. */
            break;
    }

    close(sock2);

    exit(0);
}
