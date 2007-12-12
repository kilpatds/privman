/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * msghdr.c
 * An encapsulation layer for msghdr structures, cause that's the worst
 * system-level API I have ever seen.
 *
 * $Id: msghdr.c,v 1.17 2003/04/10 00:25:52 dougk Exp $
 */
 
#include "../config.h"

#include "msghdr.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <syslog.h>
#include <errno.h>

/*
 * 1: Data structure comments.
 *
 * struct iovec {
 *      void *  iov_base        Pointer to a block of memory.
 *      int     iov_len         Size of the block of memory.
 * }
 *
 * struct msghdr {
 *     void     *msg_name       Used for non connected sockets (UDP).  Optional
 *     socklen_t msg_namelen    Size of the address aboce
 *     iovec    *msg_iov        Pointer to ARRAY of iovec structures.
 *     size_t    msg_iovlen     Number of iovecs in array.
 *     cmsghdr  *msg_control    Pointer to ARRAY of ancillary data buffers
 *     socklen_t control        total length in bytes of above buffer
 *     int       msg_flags      Flags on received messages.  Don't set.
 * }
 *
 * struct cmsghdr {
 *      socklen_t       cmsg_len        Size in bytes of this record
 *      int             cmsg_level      Originating protocol
 *      int             cmsg_type       protocol-specific type
 *      u_char          cmsg_data[]     message-specific data
 * }
 *
 * You will notice that the cmsghdr structure is Variable Size, and you
 * will also notice that the msghdr takes a pointer to an array of them.
 * If you know C, you will understand that This Does Not Work as an API,
 * but I didn't design this API, so don't blame me.  Now you know why the
 * lenght of the ancillary data buffer in the message is in bytes, not
 * records.
 *
 * CMSG_DATA(cmsg)              returns a pointer to cmsg->cmsg_data
 * CMSG_NXTHDR(msg,cmsg)        returns a cmsg after the current one, or NULL
 * CMSG_FIRSTHDR(msg)           returns msg->msg_controll, or NULL
 * CMSG_LEN(len)                returns the size of a cmsg record if it has
 *                              to contain "len" extra bits.
 */

/* TBD: handle malloc errors */

struct message {
    struct cmsghdr     *cmsg;
    struct iovec       *iov;    /* source for the data.         */
    size_t              iov_count;
    size_t              cur_iov;/* which iovector is currently getting filled */
    size_t              offset; /* where in the iov to start writing. */
    size_t              recv_len;/*amount of data not yet read. */
};

#ifdef LO_CMSG_DEF
#define CMSG_LEN(len) (_CMSG_DATA_ALIGN (sizeof (struct cmsghdr)) + (len))
#endif
#define cmsglen CMSG_LEN(sizeof(int))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

/* Globals: malloc can be slow, so cache a list of objects we would
 * malloc.
 * TBD: impliment this is its determined to be an issue.  Nuke the comments
 * if its determined to not.
 */

/* Clear out the values.  Don't call this on a in-use one, as you will
 * cause memory leaks.
 */
static void msg_bzero(message_t *msg)
{
#if 1
    memset(msg,0,sizeof(*msg));
#else
    msg->msg            = NULL;
    msg->cmsg           = NULL;
    msg->iov            = NULL;
    msg->iov_count      = 0;
    msg->cur_iov        = 0;
    msg->offset         = 0;
    msg->recv_len       = 0;
#endif
}

message_t *msg_new(void)
{
    message_t *retval = malloc(sizeof(message_t));

    msg_bzero(retval);

    return retval;
}

void msg_clear(message_t *msg)
{
    /* Just clear out the indexes.  We'll be smart about how we set things
     * up for sendmsg and recvmsg so that we don't transmit too much data.
     */
    msg->cur_iov = 0;
    msg->offset  = 0;
    msg->recv_len= 0;

    /* If the cmsg exists, zero it out, so we know not to send it */
    if (msg->cmsg) {
        memset(msg->cmsg,0,cmsglen);
    }
}

void msg_delete(message_t *msg)
{
    /* msg->iov is an array of iovec structures, each of which
     * has a data pointer.  Go through the array, clear out the
     * data.
     */
    if (msg->iov != NULL) {
        unsigned int i;
        for (i = 0 ; i < msg->iov_count; ++i) {
            struct iovec *iov = msg->iov + i;
            if (iov->iov_base != NULL)
                free(iov->iov_base);
        }
        free(msg->iov);
    }

    if (msg->cmsg != NULL) {
        free(msg->cmsg);
    }

    msg_bzero(msg);
    free(msg);
}

/* Basic scheme.
 * Start with 2 IOV structure.  Each iov structure will have a 4k buffer.
 * Each time we don't have enough space, double the iov buffer via.
 * realloc.  Its not a shooting offense in this case cause the list of
 * buffers should be small.
 */
#define MSG_PAGE 4096
static void msg_grow_buffer(message_t *msg)
{
    int old_count = msg->iov_count;
    unsigned int i;

    /* Hack for "new msg object" */
    if (old_count == 0)
        msg->iov_count = 1;

    msg->iov_count *= 2;
    msg->iov = realloc(msg->iov, sizeof(*msg->iov)*msg->iov_count);

    /* And initialize the new iov elements. */
    for (i = old_count ; i < msg->iov_count ; ++i) {
        struct iovec *iov = msg->iov + i;
        iov->iov_base = malloc(MSG_PAGE);
        iov->iov_len  = MSG_PAGE;
    }
}

void msg_addData(message_t *msg, const void *data, size_t datalen)
{
    unsigned int wrote = 0;

    /* Are we completely out of space? */
    assert(msg->offset != MSG_PAGE);
    if (msg->cur_iov >= msg->iov_count)
        msg_grow_buffer(msg);
    /* cur_iov is an index, iov_count is a count, so 1 different.
     * offset is an index, MSG_PAGE is a count, so 1 different
     */

    while (wrote < datalen) {
        /* Finish out one row. */
        int write_size = MIN(datalen - wrote, MSG_PAGE - msg->offset);

        memcpy( ((char*)msg->iov[msg->cur_iov].iov_base)+msg->offset,
                (char*)data + wrote, write_size);

        wrote += write_size;
        msg->offset += write_size;

        /* Do we need to wrap to the next row? */
        if (msg->offset >= MSG_PAGE) {
            msg->offset = 0;
            msg->cur_iov += 1;
        }
        /* Do we need to get more space? */
        if (msg->cur_iov >= msg->iov_count)
            msg_grow_buffer(msg);
    }
}

void msg_addInt (message_t *msg, int i) {
    msg_addData(msg, &i, sizeof(i));
}

void msg_addPtr (message_t *msg, const void *p) {
    msg_addData(msg, &p, sizeof(p));
}

void msg_addChar(message_t *msg, char c) {
    msg_addData(msg, &c, sizeof(c));
}

void msg_addString(message_t *msg, const char *s) {
    size_t len = (s != NULL ? strlen(s) : 0);
    msg_addInt(msg, len);
    msg_addData(msg, s, len);
}

/* Ok.  Assume that the only use of the cmsg header is to carry a single
 * FD across.  You want more than one FD?  Send it twice.
 */
void msg_setFd(message_t *msg, int fd)
{
    if (msg->cmsg != NULL && msg->cmsg->cmsg_len != 0) {
        syslog(LOG_ERR,"msg_setFD ran out of ancillary data space.");
        abort();
    }
    if (msg->cmsg == NULL)
        msg->cmsg               = malloc(cmsglen);
    msg->cmsg->cmsg_len         = cmsglen;
    msg->cmsg->cmsg_level       = SOL_SOCKET; /* protocol family */
    msg->cmsg->cmsg_type        = SCM_RIGHTS; /* fd is an access token. */

    *((int*)CMSG_DATA(msg->cmsg))=fd;
}


/*
 * msg->recvmsg() resets the indexes.  So now its not "where did I
 * stop writing", its "where did I stop reading".
 */
size_t msg_getData(message_t *msg, void *buffer, size_t bufferlen)
{
    unsigned int wrote = 0;

    /* Short circuit if nothing */
    if (msg->iov == NULL || msg->recv_len <= 0)
        return 0;
    /* recv_len is the data not yet read.  wrote is the data read
     * so far this call.
     * while the buffer's not full, and the message isn't empty */
    while (wrote < bufferlen && wrote < msg->recv_len
            && msg->cur_iov < msg->iov_count) {
        /* write enough to fill the buffer, empty the message, or
         * finish off the current iov, whichever is least. */
        int write_size = MIN(MIN(wrote - msg->recv_len, bufferlen - wrote),
                            MSG_PAGE - msg->offset);

        memcpy( (char*)buffer + wrote,
                ((char*)msg->iov[msg->cur_iov].iov_base)+msg->offset,
                write_size);

        wrote += write_size;
        msg->offset += write_size;

        /* Do we need to wrap to the next row? */
        if (msg->offset >= MSG_PAGE) {
            msg->offset = 0;
            msg->cur_iov += 1;
        }
    }
    msg->recv_len -= wrote;
    return wrote;
}

/* TBD: These methods are all vulnerable to malformed messages. */
char msg_getChar(message_t *msg)
{
    char retval;
    msg_getData(msg, &retval, sizeof(retval));
    return retval;
}

int  msg_getInt (message_t *msg)
{
    int retval;
    msg_getData(msg, &retval, sizeof(retval));
    return retval;
}

void * msg_getPtr (message_t *msg)
{
    void *retval;
    msg_getData(msg, &retval, sizeof(retval));
    return retval;
}

void msg_getString(message_t *msg, char *buffer, size_t bufferlen) {
    size_t stringlen = msg_getInt(msg);
    size_t readlen = MIN(stringlen, bufferlen);

    msg_getData(msg, buffer, readlen);
    /* The message that comes across is not null terminated.  If
     * we have space, terminate for them.
     */
    if (stringlen < bufferlen) 
        buffer[stringlen] = '\0';

    /* And throw away the rest. */
    msg->offset += (stringlen - readlen);
    if (msg->offset > MSG_PAGE) {
        msg->cur_iov += (msg->offset / MSG_PAGE);
        msg->offset %= MSG_PAGE;
        msg->recv_len -= stringlen;
    }
}

char *msg_getAllocStr(message_t *msg, size_t maxlen) {
    char *retval;
    size_t stringlen = msg_getInt(msg);

    if (maxlen <= 0)
        maxlen = 4096; /* Random default size */

    /* the string is not null terminated, so make sure we have the space */
    maxlen = MIN(maxlen-1, stringlen);

    retval = malloc(maxlen+1);
    if (retval == NULL) {
        syslog(LOG_ERR,"msg_getAllocStr: No Mem");
        errno = ENOMEM;
        return NULL;
    }
    msg_getData(msg, retval, maxlen);
    retval[maxlen] = '\0';
    /* Throw away any remaining */
    if (msg->offset > MSG_PAGE) {
        msg->cur_iov += (msg->offset / MSG_PAGE);
        msg->offset %= MSG_PAGE;
        msg->recv_len -= stringlen;
    }

    return retval;
}


int msg_getFd  (message_t *msg)
{
    if (msg->cmsg == NULL || msg->cmsg->cmsg_len != cmsglen
            || msg->cmsg->cmsg_level != SOL_SOCKET
            || msg->cmsg->cmsg_type  != SCM_RIGHTS) {
        syslog(LOG_ERR,"msg_getFd: No FD in message.");
        return -1;
    }

    return *((int*)CMSG_DATA(msg->cmsg));
}

int msg_sendmsg(message_t *msg, int fd)
{
    /* Ok.  Create the actual structure for the syscall, invoke the
     * syscall.  This function should not nuke anything...
     */
    /* To send the minimum amount of data, we need to edit the
     * last iov, and then fix after.
     */
    struct msghdr sys_msg;
    int rval;
   
    msg->iov[msg->cur_iov].iov_len = msg->offset+1;
    sys_msg = (struct msghdr){
        NULL, 0, msg->iov, msg->cur_iov+1,
	(typeof(sys_msg.msg_control))msg->cmsg,
	cmsglen, 0
    };

    if (msg->cmsg == NULL || msg->cmsg->cmsg_len == 0) {
        sys_msg.msg_control     = 0;
        sys_msg.msg_controllen  = 0;
    }

    rval = sendmsg(fd, &sys_msg, 0);

    msg->iov[msg->cur_iov].iov_len = MSG_PAGE;
    return rval;
}

int msg_recvmsg(message_t *msg, int fd)
{
    /* Nuke the contents of the current msg.  Make sure we have enough
     * space for most sane things...
     *
     * Also, be robust against EINTR.
     */
    struct msghdr sys_msg;
    int rval;
   
    if (msg->iov == NULL)
        msg_grow_buffer(msg);
    if (msg->cmsg == NULL) {
        msg->cmsg               = malloc(cmsglen);
        msg->cmsg->cmsg_len     = cmsglen;
    }
    /* Reset our read indexes. */
    msg->offset = 0;
    msg->cur_iov = 0;

    sys_msg = (struct msghdr){
        NULL, 0, msg->iov, msg->iov_count,
	(typeof(sys_msg.msg_control))msg->cmsg,
	cmsglen, 0
    };

    do {
        rval = recvmsg(fd, &sys_msg, 0);
    } while (rval == -1 && errno == EINTR);

    msg->recv_len = rval;
    return rval;
}

