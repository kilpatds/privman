/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * privman.cc 
 * Provides the server half of the process.  This half retains priviledge
 * and should be nei-invulnerable.
 *
 * $Id: privman.cc,v 1.59 2007/12/12 22:26:13 kilpatds Exp $
 */
#include "../config.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <pwd.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <syslog.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include <set>
#include <map>
#include <string>
#include <sstream>

#include "privman.h"
#include "msghdr.h"

#include "types.h"
#include "priv_impl.h"

#ifdef __cplusplus
#define UNUSED(p)
#else
#define UNUSED(p) p __attribute((unused))
#endif

extern char **environ;

/* Globals */
int             privmand_fd     = -1;    /* FD to talk to the other process */

pid_t           child_pid       = 0;

static bool     p_wait_on_child = true;

/* The config for this invocation.  Not static so that the parser can
 * find it to set it.  Parser run from priv_init.
 */
config_t               *config;


/* Have to wrap wait.  Go ahead, ask why... :) */
/* "object" data for mywait and the signal function. */
static int mywait_status_v[4];
static int mywait_pid_v[4];
static struct rusage mywait_rusage_v[4];
static int mywait_i = 0;
#define sizeof_array(a) (sizeof(a) / sizeof(a[0]))

static void sigchld_handler(int UNUSED(i)) {
    do { 
        mywait_pid_v[mywait_i] = wait4(-1, mywait_status_v + mywait_i,
                                            WNOHANG,
                                            mywait_rusage_v + mywait_i);
        if (mywait_pid_v[mywait_i] <= 0 )
            break;
        mywait_i = (mywait_i + 1) % sizeof_array(mywait_status_v);
    } while (1);
}
/* Overhead for sigaction */
static struct sigaction child_sigaction;

/* No support for options. */
static pid_t mywait4(pid_t pid, int *status, int options, struct rusage *usage)
{
    unsigned i;
    int rc;
    if (pid < -1) {
        errno = EINVAL;
        return -1;
    }
    do {
        for (i = 0 ; i < sizeof_array(mywait_status_v) ; ++i) {
            if (mywait_pid_v[i] < 1)
                continue; /* skip this one. */
            if (pid == -1 || mywait_pid_v[i] == pid) {
                if (status != NULL)
                    *status = mywait_status_v[i];
                if (usage != NULL)
                    *usage = mywait_rusage_v[i];
                rc = mywait_pid_v[i];

                mywait_pid_v[i] = 0;
                return rc;
            }
        }
    } while (!(options & WNOHANG) &&
            select(0,NULL,NULL,NULL,NULL) == -1 && errno == EINTR);
    return -1;
}

/* Dispatch table */
static std::map< enum commands, void(*)(message_t*) > function_map;

static inline
void freeArgv(char * argv[])
{
    for (int i = 0; argv[i] != NULL; ++i)
        free(argv[i]);
    free(argv);
}

static inline
char *msg_getAllocStr(message_t *msg, size_t maxlen, const char *errormsg) {
    char *rv = msg_getAllocStr(msg, maxlen);
    if (rv == NULL)
        boom(errormsg);
    return rv;
}

typedef enum {
    at_none             = -1,
    at_read_only,
    at_read_write,
    at_append_only,
    at_unlink
} accessType_t;

static accessType_t openAccessType(int flags) {
    if ((flags & 3) == O_RDONLY)
        return at_read_only;
    else if (((flags & 3) == O_WRONLY) && (flags & O_APPEND))
        return at_append_only;
    else if (((flags & 3) == O_RDWR) || (flags & 3) == O_WRONLY)
        return at_read_write;
    else
        return at_none;
}

static bool openPerm(const char *path, accessType_t type)
{
    /* MAC check here. TBD: use real globs instead of this hack */
    /* Hack:
     *   1) Path is in set.  Go home happy.
     *   2) /first/bit/of/path/[*] is in set.  Go home happy.
     */
    /* Use the "type" enum to index into the list[] array. */
    path_list          *list[] = {
                            &(config->open_ro),
                            &(config->open_rw),
                            &(config->open_ao),
                            &(config->unlink)
                        };
    char                testpath[MAXPATHLEN+1];
    char               *offset;

    if (type == at_none)
        return false;

    strncpy(testpath, path, sizeof(testpath)-2);
    testpath[sizeof(testpath)-2] = '\0';
    offset = testpath + strlen(path); /* char* cause that's what rindex
                                       * returns */
    while (offset != NULL) {
        memcpy(testpath, path, offset - testpath);
        if ( *offset == '/' ) { /* We have a directory.  Look for a glob */
            offset[1] = '*'; /* See the -2 above for your "space" question */
            offset[2] = '\0';
        }

        if (list[type]->count(testpath) != 0)
            break;

        /* Chop off the last element, and loop */
        *offset = '\0';
        offset = rindex(testpath, '/');
    }
    if (offset == NULL)
        return false;

    return true;
}

/* True is "user" is mentioned in a runas statement.
 * Or if '*' is mentioned, and user is not root.
 */
static bool runasPerm(const char *user)
{
    if (user == NULL || user[0] == '\0' || !strcmp(user, "*"))
        return false;
    if (config->user.count(user) > 0)
        return true;
    if (config->user.count("*") > 0) {
        struct passwd *pw = getpwnam(user);
        if (pw == NULL || pw->pw_uid == 0)
            return false;
        return true;
    }
    return false;
}

static void sendEPERM(message_t *msg, const char *reason)
{
    msg_initResponce(msg, -EPERM);
    if (reason != NULL)
        syslog(LOG_NOTICE, "%s", reason);
    msg_sendmsg(msg, privmand_fd, "sendEPERM(sendmsg)");
}


/* Like "realpath", but can cope with a missing file in a non
 * missing directory.  Might not handle dangling symlinks right. XXX
 */
static bool myrealpath(const char *path, char *resolved)
{
    char       *rv;
    char        buf[PATH_MAX+1];
    char        last_elm[PATH_MAX+1];
    char       *last_slash;
    int         n;

    strncpy(buf, path, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    /* deletegate to "realpath" */
    rv = realpath(buf, resolved);
    if (rv != NULL || errno != ENOENT)
        return rv != NULL;

    /* Ok, doesn't exist.  Chop off the filename and save it.
     * Huge buffer way to big.  *shrug*
     */
    last_slash = rindex(buf, '/');
    if (last_slash == NULL)
        return false;

    strncpy(last_elm, last_slash, sizeof(last_elm)-1);
    last_elm[sizeof(last_elm)-1] = '\0';

    /* Now chop off the last bit, and try the directory */
    *last_slash = '\0';

    rv = realpath(buf, resolved);
    if (rv == NULL)
        return false;

    /* Add it back, and call it a day */
    n = strlen(resolved);
    strncpy(resolved+n, last_elm, PATH_MAX-n);

    return true;
}

/* Handle certain requests */

static void unlinkFile(message_t *msg) {
    char       *path;
    char       *cwd;
    char        canpath[MAXPATHLEN+1];
    int         retval, n;

    cwd   = msg_getAllocStr(msg, MAXPATHLEN+1, "unlinkFile: bad cwd");
    path  = msg_getAllocStr(msg, MAXPATHLEN+1, "unlinkFile, path path");

    /* Canacolize the path, so that a comparison with the
     * allowed list makes sence, and in case the client did a chdir.
     *
     * The client sends us "getcwd()" output, so no trailing '/'.  If
     * the client wants to lie to us for this message, no great foul.
     * He gets no file.
     */

    n = strlen(cwd);
    if (path[0] == '/') { /* absolute or not? */
        /* Abs: nuke cwd with path, then realpath it. */
        strncpy(cwd, path, sizeof(cwd) - n);
    } else {
        cwd[n++] = '/'; /* Path seperator */
        strncpy(cwd + n, path, sizeof(cwd) - n);
    }

    if (!myrealpath(cwd, canpath)) {
        /* Could be lots of reasons.  So lets confuse em with whatever
         * realpath said.
         */
        msg_initResponce(msg, -errno);
        msg_sendmsg(msg, privmand_fd, "unlinkFile(sendmsg)");
    }

    /* MAC check here. TBD: use real globs instead of this hack */
    if (!openPerm(canpath, at_unlink)) {
        sendEPERM(msg, "Unauthorized attempt to unlink");
    } else {
        /* Ok, now do it. */
        retval = unlink(canpath);
        if (retval < 0) {
            msg_initResponce(msg, -errno);
            syslog(LOG_WARNING, "priv_unlink(unlink): %m");
        } else {
            msg_initResponce(msg, 0);
        }
        msg_sendmsg(msg, privmand_fd, "unlinkFile(sendmsg)");
    }

    free(path); free(cwd);
}

/* Handle an "open file" request */
static void openFile(message_t *msg) {
    char       *path;
    char        cwd[MAXPATHLEN+1]; /* Has to be this big. */

    char        canpath[MAXPATHLEN+1];
    int         flags, mode;
    int         rfd = 0;
    int         n;

    /* Open file specified, return the fd. */
    /* arg1 = open mode
     * arg2 = creation mode (optional)
     * arg3 = pathname
     *
     * Returns
     * arg1 = 0 or -1
     * arg2 = errno (if arg1 < 0)
     */

    flags = msg_getInt(msg);
    mode  = msg_getInt(msg);
    msg_getString(msg, cwd, MAXPATHLEN+1);
    path  = msg_getAllocStr(msg, MAXPATHLEN+1, "openFile, path path");

    /* Canacolize the path, so that a comparison with the
     * allowed list makes sence, and in case the client did a chdir.
     *
     * The client sends us "getcwd()" output, so no trailing '/'.  If
     * the client wants to lie to us for this message, no great foul.
     * He gets no file.
     */

    n = strlen(cwd);
    if (path[0] == '/') { /* absolute or not? */
        /* Abs: nuke cwd with path, then realpath it. */
        strncpy(cwd, path, sizeof(cwd) - n);
    } else {
        cwd[n++] = '/'; /* Path seperator */
        strncpy(cwd + n, path, sizeof(cwd) - n);
    }

    if (!myrealpath(cwd, canpath)) {
        /* Could be lots of reasons.  So lets confuse em with whatever
         * realpath said.
         */
        msg_initResponce(msg, -errno);
        msg_sendmsg(msg, privmand_fd, "openFile(sendmsg)");
    }

    /* MAC check here. TBD: use real globs instead of this hack */
    if (!openPerm(canpath, openAccessType(flags))) {
        std::stringstream errmsg;
        errmsg << "Unauthorized attempt open of type "
            << openAccessType(flags);
        sendEPERM(msg, errmsg.str().c_str());
    } else {
        /* Ok, now do it. */
        rfd = open(canpath,flags,mode);
        if (rfd < 0) {
            msg_initResponce(msg, -errno);
            syslog(LOG_WARNING, "msg_open_file(open): %m");
        } else {
            msg_initResponce(msg, 0);
            msg_setFd(msg,rfd);
        }
        msg_sendmsg(msg, privmand_fd, "openFile(sendmsg)");
        close(rfd); /* prevent the leak */
    }

    free(path);
}

static void bindPort(message_t *msg) {
    int                 sockfd;
    struct sockaddr_in *addr;
    struct sockaddr_in6*addr6;
    socklen_t           addrlen;
    int                 retval;

    addrlen     = msg_getInt(msg);
    addr        = (struct sockaddr_in*)malloc(addrlen);
    msg_getData(msg, addr, addrlen);
    addr6       = (struct sockaddr_in6*)addr;
    sockfd      = msg_getFd(msg);

    /* Permission check */
    /* If its an INET family (cause that's the only ports we know how to
     * check,
     * and the addrlen is long enough
     * and the port is in the config file....
     */
    int port = -1; /* in_port_t is uint16, so -1 can be a token in int32 */
    if (addr->sin_family == AF_INET && addrlen >= sizeof(sockaddr_in))
        port = addr->sin_port;
    else if (addr6->sin6_family == AF_INET6 && addrlen >= sizeof(sockaddr_in6))
        port = addr6->sin6_port;

    if (sockfd >= 0 && port != -1
            && ( config->bind_port.count(ntohs(port)) > 0
                || config->bind_port.count(ntohs(0)) > 0)) /* 0 is a wildcard */
    {
        retval      = bind(sockfd, (struct sockaddr*)addr, addrlen);

        if (retval < 0)
            retval = -errno; /* since it'll be used for this anyway. */

        msg_initResponce(msg, retval);
        msg_sendmsg(msg, privmand_fd, "bindPort(sendmsg)");
    } else {
        /* Permission denied */
        sendEPERM(msg, "Unauthorzed attempt to bind to port.");
    }

    close(sockfd); /* don't leak this. */
}
 
#ifdef HAVE_LIBPAM

/* TBD: multiple conversion functions. */
static       struct pam_conv    pconv;    /* server side. */

/* PAM conversion function.  We pass the work back to the other
 * side.  The assumption is that the other side is currently
 * waiting in a priv_pam_foo() call, and will recoginize the
 * message.
 *
 * Don't bother passing app_ptr, as it won't be right anyway.  The other
 * side has it.  resp is an out value, not an in value.
 */

static int convert_punt(int num_msg,
        PAM_CONV_FUNC_CONST struct pam_message **messages,
        struct pam_response **resp,
        void * UNUSED(app_ptr))
{
    message_t                  *msg = msg_new();
    struct pam_response        *reply;
    int                         retval, i;

    msg_initResponce(msg, PRIV_PAM_RUN_CONV);
    msg_addInt(msg,num_msg);
    for (i = 0; i < num_msg; ++i) {
        msg_addInt(msg,messages[i]->msg_style);
        msg_addString(msg,messages[i]->msg);
    }

    msg_sendmsg(msg, privmand_fd, "convert_punt(sendmsg)");

    msg_initResponce(msg, 0);
    msg_recvmsg(msg, privmand_fd, "convert_punt(recvmsg)");

    retval = msg_getInt(msg);
    reply = (struct pam_response*)malloc(sizeof(*reply) * num_msg);
    for (i = 0; i < num_msg; ++i) {
        reply[i].resp = msg_getAllocStr(msg, PAM_MAX_RESP_SIZE,
                "convert_punt: bad responce");
        reply[i].resp_retcode = msg_getInt(msg);
    }

    msg_delete(msg);

    *resp = reply;
    return retval;
}

static void pamStart(message_t *msg)
{
    pam_handle_t       *handle;
    int                 retval;
    char               *service;
    char               *user;

    service = msg_getAllocStr(msg, 128, "pamStart: bad service");
    user    = msg_getAllocStr(msg, 128, "pamStart: bad user");

    /* msghdr combines "" and NULL.  pam_start doens't like "", 
     * so make sure it gets NULL.
     */
    if (user[0] == '\0') {
        free(user);
        user = NULL;
    }
    pconv = (struct pam_conv){ convert_punt, 0};

    retval = pam_start(service, user, &pconv, &handle);

    msg_initResponce(msg, PRIV_PAM_RC);
    msg_addInt(msg,retval);
    msg_addPtr(msg, handle);

    msg_sendmsg(msg, privmand_fd, "pamStart(sendmsg)");
    free(service);
    if (user != NULL)
        free(user);
}

static void pamAuthenticate(message_t *msg)
{
    pam_handle_t *pamh;
    int flags, rc;

    pamh  = (pam_handle_t*)msg_getPtr(msg);
    flags = msg_getInt(msg);

    rc = pam_authenticate(pamh, flags);

    if (rc == PAM_SUCCESS && config->auth_allow_rerun) {
        char *authenticating_user;
        int rc2;
        rc2 = pam_get_item(pamh, PAM_USER,
                (PAM_GET_ITEM_CONST void**)(&authenticating_user));
        if (rc2 == PAM_SUCCESS)
            config->user.insert(authenticating_user);
    }

    /* This isn't a call to run the conv func */
    msg_initResponce(msg, PRIV_PAM_RC);
    msg_addInt(msg, rc);
    msg_sendmsg(msg, privmand_fd, "pamSimpleFunc(sendmsg)");
}

static void pamSimpleFunc(message_t *msg, int (*func)(pam_handle_t*,int))
{
    pam_handle_t *pamh;
    int flags, rc;

    pamh  = (pam_handle_t*)msg_getPtr(msg);
    flags = msg_getInt(msg);

    rc = func(pamh, flags);

    /* This isn't a call to run the conv func */
    msg_initResponce(msg, PRIV_PAM_RC);
    msg_addInt(msg, rc);
    msg_sendmsg(msg, privmand_fd, "pamSimpleFunc(sendmsg)");
}

static void pamSetItem(message_t *msg)
{
    pam_handle_t       *pamh;
    int                 type, rc;

    pamh = (pam_handle_t*)msg_getPtr(msg);
    type = msg_getInt(msg);

    assert(type != PAM_CONV);

    if (type == PAM_FAIL_DELAY) {
        void   *item = msg_getPtr(msg);
        rc = pam_set_item(pamh, type, item);
    } else {
        char    buf[1024];
        msg_getString(msg, buf, sizeof(buf)-1);
        buf[sizeof(buf)-1] = '\0';
        rc = pam_set_item(pamh, type, buf);
    }

    msg_clear(msg);

    msg_addInt(msg, PRIV_PAM_RC);
    msg_addInt(msg, rc);

    msg_sendmsg(msg, privmand_fd, "pamSetItem(sendmsg)");
}

static void pamGetItem(message_t *msg)
{
    pam_handle_t       *pamh;
    int                 type, rc;
    void               *item;

    pamh = (pam_handle_t*)msg_getPtr(msg);
    type = msg_getInt(msg);

    assert(type != PAM_CONV);

    rc = pam_get_item(pamh, type, (PAM_GET_ITEM_CONST void **)(&item));

    msg_clear(msg);

    msg_addInt(msg, PRIV_PAM_RC);
    msg_addInt(msg, rc);

    if (rc == PAM_SUCCESS) {
        if (type != PAM_FAIL_DELAY) {
            msg_addString(msg, (char*)item);
        } else {
            msg_addPtr(msg, item);
        }
    }

    msg_sendmsg(msg, privmand_fd, "pamGetItem(sendmsg)");
}
#endif

static void exitServer(message_t *UNUSED(msg)) {
    if (p_wait_on_child) {
        /* This will cause control_loop to break out of the loop */
        close(privmand_fd);
    } else {
        /* Simple. */
        _exit(0);
    }
}

static void privWait4(message_t *msg) {
    pid_t               pid;
    int                 options;
    int                 status;
    struct rusage       ruse;

    int                *s = NULL;
    struct rusage      *r = NULL;
    int                 flags;

    pid       = msg_getInt(msg);
    options   = msg_getInt(msg);
    flags     = msg_getInt(msg);
    if (flags & WANTS_STATUS)
        s = &status;
    if (flags & WANTS_RUSAGE)
        r = &ruse;

    pid = mywait4(pid, s, options, r);

    msg_clear(msg);

    if (pid < 0)
        msg_initResponce(msg, -errno);
    else {
        msg_initResponce(msg, pid);

        if (flags & WANTS_STATUS)
            msg_addInt(msg, status);
        if (flags & WANTS_RUSAGE)
            msg_addData(msg, &ruse, sizeof(ruse));
    }

    msg_sendmsg(msg, privmand_fd, "privWait4(sendmsg)");
}

static void forkProcess(message_t *msg) {
    /* Client requests fork().
     * We create new pipe fd, hand back to client.
     *    Fork.
     *    Child privmand listens on fd.
     *    We close fd.
     *
     * Can't quite do the same as we do in respawnAs, (and thus share code)
     * as the child doesn't exit, it fork()s.
     */
    int         fds[2], n;

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) < 0)
        boom("forkProcess(socketpair)");

    msg_initResponce(msg, 0);
    msg_setFd(msg, fds[0]);
    msg_sendmsg(msg, privmand_fd, "forkProcess(sendmsg)");

    close(fds[0]);

    n = fork();
    if (n < 0)
        boom("forkProcess(fork)");
    else if (n > 0) {
        /* Parent.  Close the FD's */
        close(fds[1]);
    } else {
        /* child */
        close(privmand_fd);
        privmand_fd = fds[1];
        p_wait_on_child = false;
    }
}

/* Table needed for popen.  We have to be able to map a handle to 
 * a File Descriptor.. because CMD_PCLOSE requires the handle that
 * POPEN_AS returned so that it knows which process is expected to end.
 *
 * Maps fd to pid.
 */
static std::map<int, pid_t> file_pid_map;

/* Static function used for rerunas pointer. */
static void priv_popen_impl(char * const arg[])
{
    char       *argv[] = { "sh", "-c", arg[0], 0 };

    /* fd already set up. */
    execve("/bin/sh", argv, environ);
    _exit(-1);
}


static void popenImpl(message_t *msg) {
    char       *command;
    int         type; /* 0 or 1, write, or read */
    char       *user;
    char       *root;
    int         i;
    int         fds[2];
    int         pid;

    /* 0: Get the args. */
    command = msg_getAllocStr(msg, 4096, "popenImpl(bad command)");
    type = msg_getInt(msg);
    user = msg_getAllocStr(msg, 32, "popenImpl(bad user)");
    root = msg_getAllocStr(msg, PATH_MAX+1, "popenImpl(bad chroot)");
    if (type < 0 || type > 1)
        boom("popenImpl(bad type)");

    /* MAC check */
    if (!runasPerm(user)) {
        sendEPERM(msg, "Unauthorized rerunAs target");
        goto cleanup;
    }

    /* 1: Create the shared fds. */
    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) < 0)
        boom("popenImpl(socketpair)");

    /* 2: Fork. */
    pid = fork();
    if (pid < 0)
        boom("popenImpl(fork)");
    else if (pid == 0) { 
        /* Just to make sure. */
        close(privmand_fd);
        privmand_fd = -1;
        /* Close all non shared fds */
        for (i=255 ; i > 3; --i) {
            if (i != fds[0])
                close(i);
        }
        if (type)
            dup2(fds[0], STDOUT_FILENO);
        else
            dup2(fds[0], STDIN_FILENO);
        /* execute shell .  This won't return since priv_popen_impl won't */
        setup_child( priv_popen_impl, &command, user, root);
    }
    /* 4: Parent, save pid and fd in map for future pclose. */
    close(fds[0]);
    file_pid_map[fds[1]] = pid;

    /* return fd */
    msg_clear(msg);

    msg_initResponce(msg, fds[1]); /* Pass as a handle. */
    msg_setFd(msg, fds[1]);
    msg_sendmsg(msg, privmand_fd, "popenImpl(sendmsg)");
    close(fds[1]); /* We dont' need it anymore */
cleanup:
    free(command);
    free(user);
    free(root);
    
}

static void pcloseImpl(message_t *msg) {
    int         fd;
    int         pid;
    int         rc;

    /* Get args. */
    fd = msg_getInt(msg);
    msg_clear(msg);
    if (file_pid_map.count(fd) == 0) {
        msg_initResponce(msg, -EPERM);
        syslog(LOG_NOTICE, "%s", "pcloseImpl(bad handle)");
    } else {
        /* Get pid from map, remove from map. */
        pid = file_pid_map[fd];
        file_pid_map.erase(fd);
        /* Collect the status.  ie, Blocking. */
        if (wait4(pid, &rc, 0, NULL) < 0)
            rc = -EINVAL;

        msg_initResponce(msg, rc);
    }
    msg_sendmsg(msg, privmand_fd, "pcloseImpl(sendmsg)");
}


static void daemonProcess(message_t *msg) {
    /* Daemon.
     * 1) Fork, parent quits.  No mucking with global state
     *    and the child should be fine.
     * 2) Setsid.  This detaches us from the controlling terminal,
     *    so ^C won't work.
     * 3) How do I handle waiting on the child?  I don't.  It quits,
     *    I go away.  So set the p_wait_on_child flag.
     */
    int n;
 
    n = fork();
    if (n == 0) {
        /* child.  See above. */
        setsid(); /* Detach */

        /* Handle stdio.  strace for output? */
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "a", stderr);

        p_wait_on_child = false;
        /* Send a success message */
        msg_clear(msg);
        msg_initResponce(msg, 0);
        msg_sendmsg(msg, privmand_fd, "daemonProcess(sendmsg)");
    } else if (n > 0) {
        /* Parent.  This is easy. */
        _exit(0);
    } else if (n < 0) {
        /* Error.  Panic and fall down? */
        boom("daemonProcess(fork)");
    }
}

static void rerunAsProcess(message_t *msg)
{
    /* Flags tells us which child is allowed to talk to the privmand
     * server.
     */
    char      **args;
    char       *user, *root;
    void        (*fnptr)(char * const *);
    int         flags;

    flags = msg_getInt(msg);
    fnptr = (void (*)(char* const *))msg_getPtr(msg);
    args  = msg_getArgv(msg);
    user  = msg_getAllocStr(msg, 32, "rerunAsProcess: bad user");
    root  = msg_getAllocStr(msg, MAXPATHLEN+1, "rerunAsProcess: bad root");

    /* MAC checks. */
    if (!runasPerm(user)) {
        sendEPERM(msg, "Unauthorized rerunAs target");
        goto cleanup;
    }

    if (flags & PRIV_RR_OLD_SLAVE_MONITORED) {
        pid_t child2 = fork();
        if (child2 == -1) {
            boom("respawnAsProcess(fork2)");
        } else if (child2 == 0) {
            close(privmand_fd); /* cut connection to original privmand. */

            setup_child(fnptr, args, user, root);
        } else {
            msg_initResponce(msg, child2);
            msg_sendmsg(msg, privmand_fd, "respawnAsProcess(sendmsg)");
        }
    } else {
        /* Tell the original slave to go away. */
        msg_clear(msg);
        msg_initResponce(msg, 0);
        msg_sendmsg(msg, privmand_fd, "rerunAsProcess(sendmsg)");

        config->unpriv_user = user; /* Assignments, not copies. */
        config->unpriv_jail = root; /* Just for consistency sake */
        /* This will run the client function, then drop back
         * through here, as both the parent and the child.
         */
        priv_sep_init(0, fnptr, args, user, root);
    }

cleanup:
    free(user); free(root);
    freeArgv(args);
}

static void respawnAsProcess(message_t *msg)
{
    char      **args;
    char       *user, *root;
    void        (*fnptr)(char * const *);

    fnptr = (void (*)(char* const *))msg_getPtr(msg);
    args = msg_getArgv(msg);
    user = msg_getAllocStr(msg, 32, "rerunAsProcess: bad user");
    root = msg_getAllocStr(msg, MAXPATHLEN+1, "rerunAsProcess: bad root");

    /* MAC checks. */
    if (!runasPerm(user)) {
        sendEPERM(msg, "Unauthorized respawnAs target");
        goto clean;
    }

    /* Fork the monitor.   Parent returns.  The rest of this method takes
     * place in the child.
     */
    switch(fork()) {
    case -1:
        boom("respawnAsProcess(fork)");
        /* NOTREACHED */
    default:
        /* Parent. */
        msg_initResponce(msg, 0);
        msg_sendmsg(msg, privmand_fd, "respawnAsProcess(sendmsg)");
        goto clean;
    case 0:
        /* Child. Fall through. */
        /* Close off connection with old monitor & old slave */
        close(privmand_fd);
        privmand_fd = -1;
        break;
    }

    config->unpriv_user = user; /* Assignments, not copies. */
    config->unpriv_jail = root; /* Just for consistency sake */
    /* This will run the client function, then drop back
     * through here, as both the parent and the child.
     */
    priv_sep_init(0, fnptr, args, user, root);
clean:
    free(user); free(root);
    freeArgv(args);
}

/* populated by priv_register_foo in priv_client.cc.  Our copy should
 * be protected by the fork() in priv_init, so after that it should
 * not change.
 */

static void customInfo(message_t *msg)
{
    int         handle  = msg_getInt(msg);
    char      **args    = msg_getArgv(msg);
    char       *rv;
    info_fn_map_t::iterator    it;

    it = info_fn_map.find(handle);
    if (it != info_fn_map.end()) {
        rv = ((*it).second)(args);
    } else {
        errno = ENOENT;
        rv = NULL;
    }

    msg_initResponce(msg, PRIV_PAM_RC);
    if (rv == NULL) {
        msg_addInt(msg, -errno);
    } else {
        msg_addInt(msg, 0);
        msg_addString(msg, rv);
    }

    msg_sendmsg(msg, privmand_fd, "customInfo(sendmsg)");

    freeArgv(args);
    free(rv);
}

static void customCap(message_t *msg)
{
    int         handle  = msg_getInt(msg);
    char      **args    = msg_getArgv(msg);
    int         rv;
    cap_fn_map_t::iterator     it;

    it = cap_fn_map.find(handle);
    if (it != cap_fn_map.end()) {
        rv = ((*it).second)(args);
    } else {
        rv = -1;
        errno = ENOENT;
    }

    msg_initResponce(msg, PRIV_PAM_RC);
    if (rv < 0) {
        msg_addInt(msg, -errno);
    } else {
        msg_addInt(msg, 0);
        msg_setFd(msg, rv);
    }

    msg_sendmsg(msg, privmand_fd, "customCap(sendmsg)");

    freeArgv(args);
}

/* Is this client allowed to make this TYPE of request.  For
 * things with finer grained permissions, do that kind of check
 * in the request handler.
 */
static bool validRequest(enum commands c) {
    if (config == NULL)
        return false;
    switch (c) {
    case CMD_OPEN:              /* Deal with it when we know what. */
    case CMD_UNLINK:            /* Deal with it when we know what. */
    case CMD_EXIT:              /* always thus. */
    case CMD_WAIT4:             /* Seems harmless */
    case CMD_CUSTOM_INFO:       /* job of other half to validate. */
    case CMD_CUSTOM_CAP:
        return true; 
    case CMD_RERUN_AS:
    case CMD_RESPAWN_AS:
    case CMD_POPEN:
    case CMD_PCLOSE:
        return config->rerunas;
    case CMD_BIND:
        return !config->bind_port.empty();
    case CMD_PAM_START:
    case CMD_PAM_AUTHENTICATE:
    case CMD_PAM_ACCT_MGMT:
    case CMD_PAM_END:
    case CMD_PAM_SETCRED:
    case CMD_PAM_OPEN_SESSION:
    case CMD_PAM_CLOSE_SESSION:
    case CMD_PAM_GET_ITEM:
    case CMD_PAM_SET_ITEM:
    case CMD_PAM_GETENV:
    case CMD_PAM_PUTENV:
    case CMD_PAM_CHAUTHTOK:
    case CMD_PAM_FAIL_DELAY:
        return config->auth;
    case CMD_FORK:
    case CMD_DAEMON:
        return config->pfork;
    }
    return false;
}

/* Go to the server.  This function is the root of the server.  It
 * initializes things, then goes into a loop listening for client
 * requests.
 */
static void control_loop(void) {
    message_t  *msg = msg_new();
    int         readlen = 0;

    /* Loop on incoming messages
     * child_pid test is for "RERUN_AS"
     */
    while (child_pid != 0 && (readlen = msg_recvmsg(msg, privmand_fd)) > 0) {
        enum commands c;
        c = (enum commands)msg_getInt(msg);

        if (!validRequest(c)) {
            sendEPERM(msg, "Unknown or not permitted request");
            continue;
        }
        /* The handler function for a given request does the responce. */
        void (*fnptr)(message_t*) = function_map[c];
        if (fnptr == NULL) {
            syslog(LOG_ERR, "libprivman: bad command (c = %c)", c);
            boom("control_loop(unknown command)");
        }
        /* Call the handler */
        fnptr(msg);

        msg_clear(msg);
    }
    msg_delete(msg);

    if (readlen < 0 && errno != EBADF)
        boom("recvmsg");
}

#ifdef HAVE_LIBPAM
#define PAM_SIMPLE_HANDLER(name, method)                                \
static void name(message_t *msg) {                                      \
    pamSimpleFunc(msg, method);                                         \
}

PAM_SIMPLE_HANDLER(pamAcctMgmt,         pam_acct_mgmt)
PAM_SIMPLE_HANDLER(pamEnd,              pam_end)
PAM_SIMPLE_HANDLER(pamSetcred,          pam_setcred)
PAM_SIMPLE_HANDLER(pamOpenSession,      pam_open_session)
PAM_SIMPLE_HANDLER(pamCloseSession,     pam_close_session)
PAM_SIMPLE_HANDLER(pamChauthtok,        pam_chauthtok)
#ifdef LO_HAVE_PAM_FAIL_DELAY
PAM_SIMPLE_HANDLER(pamFailDelay,     (int(*)(pam_handle_t*,int))pam_fail_delay)
#endif
#endif /* HAVE_LIBPAM */

void privman_serv_init(void)
{
    struct sigaction old;
    /* Set up signal handler. */
    child_sigaction.sa_handler = sigchld_handler;
    child_sigaction.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &child_sigaction, &old);

    function_map[ CMD_OPEN              ] = openFile;
    function_map[ CMD_UNLINK            ] = unlinkFile;
    function_map[ CMD_BIND              ] = bindPort;

#ifdef HAVE_LIBPAM
    function_map[ CMD_PAM_START         ] = pamStart;
    function_map[ CMD_PAM_GET_ITEM      ] = pamGetItem;
    function_map[ CMD_PAM_SET_ITEM      ] = pamSetItem;
    function_map[ CMD_PAM_AUTHENTICATE  ] = pamAuthenticate;
    function_map[ CMD_PAM_ACCT_MGMT     ] = pamAcctMgmt;
    function_map[ CMD_PAM_END           ] = pamEnd;
    function_map[ CMD_PAM_SETCRED       ] = pamSetcred;
    function_map[ CMD_PAM_OPEN_SESSION  ] = pamOpenSession;
    function_map[ CMD_PAM_CLOSE_SESSION ] = pamCloseSession;
    function_map[ CMD_PAM_CHAUTHTOK     ] = pamChauthtok;
#ifdef LO_HAVE_PAM_FAIL_DELAY
    function_map[ CMD_PAM_FAIL_DELAY    ] = pamFailDelay;
#endif
#endif /* HAVE_LIBPAM */

    function_map[ CMD_FORK              ] = forkProcess;
    function_map[ CMD_EXIT              ] = exitServer;
    function_map[ CMD_DAEMON            ] = daemonProcess;
    function_map[ CMD_WAIT4             ] = privWait4;

    function_map[ CMD_POPEN             ] = popenImpl;
    function_map[ CMD_PCLOSE            ] = pcloseImpl;

    function_map[ CMD_RERUN_AS          ] = rerunAsProcess;
    function_map[ CMD_RESPAWN_AS        ] = respawnAsProcess;

    function_map[ CMD_CUSTOM_INFO       ] = customInfo;
    function_map[ CMD_CUSTOM_CAP        ] = customCap;

    /* The server spends most of its time in here. */
    control_loop();

    /* Two ways we get here
     * 1) CMD_EXIT
     * 2) CMD_RERUN_AS/RESPAWN_AS
     *
     * RERUN_AS requires magic.  This is a second child of the
     * privmand server, so we want to drop back out to priv_init()
     */
    if (child_pid != 0) { 
        if (p_wait_on_child) {
            /* Other side closed pipe */
            int status;
            mywait4(child_pid, &status, 0, 0);
            if (WIFEXITED(status))
                _exit(WEXITSTATUS(status));
            else {
                _exit(EXIT_FAILURE);
            }
         } else {
            _exit(0);
        }
    }
}
