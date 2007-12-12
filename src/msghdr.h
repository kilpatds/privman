/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * msghdr.h
 * An encapsulation layer for msghdr structures, cause that's the worst
 * system-level API I have ever seen.
 *
 *  msg = msg_new();
 *  msg_addChar(msg, c);
 *  msg_addInt (msg, i);
 *  msg_addInt (msg, j);
 *  msg_addData(msg, path, pathlen);
 *  msg_setFd  (msg, fd);
 *  msg_sendmsg(msg, fd);
 *  msg_delete (msg);
 *
 *  msg = msg_new();
 *  while ( msg_recvmsg(msg, fd) >= 0 ) {
 *      c  = msg_getChar(msg);
 *      i  = msg_getInt (msg);
 *      j  = msg_getInt (msg);
 *      // while ( n < ... )
 *      msg_getData(pathbuf, MAXPATHLEN);
 *      fd = msg_getFd  (msg);
 *
 *      msg_clear(msg);
 *  }
 *
 * $Id: msghdr.h,v 1.6 2003/04/10 00:25:52 dougk Exp $
 */
#ifndef MSGHDR_H
#define MSGHDR_H 1

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct message message_t;

message_t      *msg_new(void);
void            msg_delete (message_t *msg);
void            msg_clear  (message_t *msg);

void            msg_addChar(message_t *msg, char c);
void            msg_addInt (message_t *msg, int i);
void            msg_addPtr (message_t *msg, const void *p); /* useless. */
void            msg_addString(message_t *msg, const char *s);
void            msg_addData(message_t *msg, const void *data, size_t datalen);
void            msg_setFd  (message_t *msg, int fd);

char            msg_getChar(message_t *msg);
int             msg_getInt (message_t *msg);
void           *msg_getPtr (message_t *msg); /* useless */
size_t          msg_getData(message_t *msg, void *buffer, size_t bufferlen);
void            msg_getString(message_t *msg, char *buffer, size_t bufferlen);
char *          msg_getAllocStr(message_t *msg, size_t maxlen);
int             msg_getFd  (message_t *msg);

int             msg_sendmsg(message_t *msg, int fd);
int             msg_recvmsg(message_t *msg, int fd);

#ifdef __cplusplus
}
#endif

#endif

