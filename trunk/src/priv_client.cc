/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * priv_client.cc
 * Provides the client half of the process.  Should be considered
 * untrusted by the privman server.
 *
 * $Id: priv_client.cc,v 1.41 2007/12/12 22:26:13 kilpatds Exp $
 */

#include "../config.h"
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <map>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include "privman.h"
#include "msghdr.h"

#include "types.h"
#include "priv_impl.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#ifdef HAVE_LIBPAM
/* Used as a cache for get/set_item */
static const void      *pam_types[20] = { 0 };
/*                                      // Strings.  void* for strings.
 *  [PAM_SERVICE]           = NULL,
 *  [PAM_USER]              = NULL,
 *  [PAM_TTY]               = NULL,
 *  [PAM_RHOST]             = NULL,
 *  [PAM_CONV]              = NULL,
 *
 *  [PAM_RUSER]             = NULL,
 *  [PAM_USER_PROMPT]       = NULL,
 *  [PAM_FAIL_DELAY]        = NULL      // This is just a function pointer
 */
#endif /* HAVE_LIBPAM */
 
#ifndef CONFIG_PATH
#define CONFIG_PATH="/etc/privman.d"
#endif
static void readConfig(const char *progname) {
    extern FILE        *yyin; /* lex's input */
    char                pathname[PATH_MAX+1] = CONFIG_PATH;
    /* Assigning a string to the buffer null-pads it */
 
    strncpy(pathname+sizeof(CONFIG_PATH)-1,progname,
            sizeof(pathname)-sizeof(CONFIG_PATH));
 
    /* fopen, cause yyin if a FILE* */
    yyin = fopen(pathname, "r");
 
    if (yyin == NULL) {
        syslog(LOG_ERR,"Error: missing privmand configuration file\n");
    } else if (yyparse() != 0) {
        syslog(LOG_ERR,"Error reading privmand configuration file\n");
    } 
    if (yyin != NULL)
        fclose(yyin);
}

#ifdef HAVE_LIBPAM
/* When requested, calls the PAM conversion function registered by
 * the client.
 */
static void handleConvert(message_t *msg)
{
    struct pam_message        **messages;
    struct pam_response        *resp;
    int                         num_msg;
    int                         i, n, rc;

    num_msg = msg_getInt(msg);
    messages = (struct pam_message**)malloc(sizeof(*messages) * num_msg);
    for (i = 0 ; i < num_msg; ++i) {
        char    buf[PAM_MAX_MSG_SIZE];
        messages[i] = (struct pam_message*)malloc(sizeof(**messages));

        messages[i]->msg_style = msg_getInt(msg);
        msg_getString(msg,buf,sizeof(buf)-1);
        buf[sizeof(buf)-1] = '\0';
        messages[i]->msg = strdup(buf);
    }

    rc = ((struct pam_conv*)pam_types[PAM_CONV])->conv(num_msg,
                /* C const fun cast */
            (PAM_CONV_FUNC_CONST struct pam_message **)messages,
            &resp, ((struct pam_conv*)pam_types[PAM_CONV])->appdata_ptr);


    msg_clear(msg);

    msg_addInt(msg,rc);
    for (i = 0; i < num_msg; ++i) {
        msg_addString(msg, resp[i].resp);
        msg_addInt(msg, resp[i].resp_retcode);
    }

    n = msg_sendmsg(msg, privmand_fd);
    if (n < 0)
        boom("handleConvert(sendmsg)");

    /* Tear down all the data. */
    for (i = 0; i < num_msg; ++i) {
        free((char*)(messages[i]->msg)); /* const cast */
        free(resp[i].resp);
    }
    free(messages);
    free(resp);
}

#endif /* HAVE_LIBPAM */


static __inline__
void wait_for_debugger(void)
{
#if defined(DEBUG)
    /* Block until the debugger unblocks us.  Gives you a known
     * place to attach the debugger.
     */
    volatile int i = 0;
    syslog(LOG_ALERT,"waiting for debugger\n");
    while (i == 0)
        sleep(1);
#endif
}

void socketfun(int sockfds[2], bool server) {
    if (server) {
        close(sockfds[1]); /* We keep [0] */
        privmand_fd = sockfds[0];
    } else {
        close(sockfds[0]); /* we keep [1] */
        privmand_fd = sockfds[1];
    }
}

void setup_child(void (*fnptr)(char * const *), char * const args[],
        const char *user, const char *root)
{
    struct passwd  *pwent;

    /* Get unpriv_user info, in case chroot changes it.
     * chroot,
     * setuid.
     */

    /* Normalize unpriv_user, root. */
    if (user == NULL || (strcmp(user, "") == 0))
        user = "nobody";
    else if (geteuid() != 0)
        boom("Specified user, when allowed to use arbitrary users");

    if (root == NULL || (strcmp(root, "") == 0))
        root = "/";

    /* getpwnam */
    pwent = getpwnam(user);
    /* Don't know if its a static pointer, or malloced and I'm allowed
     * to clear it, so just leak it.
     */

    if (pwent == NULL) {
        syslog(LOG_ERR, "getpwnam failed on unpriv user %s", user);
        boom("setup_child(getpwnam)");
    }

    /* chroot */
    if (strcmp(root,"/") != 0) {
        if (chroot(root) < 0) {
            syslog(LOG_ERR, "chroot to %s\n", root);
            boom("setup_child(chroot)");
        }

        if (chdir("/") < 0) {
            syslog(LOG_ERR, "chroot to %s\n", root);
            boom("setup_child(chdir)");
        }
    }

    int newuid = pwent->pw_uid;
    int newgid = pwent->pw_gid;

    // The setuid(other non-priv user) case.  We should have blown up ablove
    // if a specific user was given in the config file, as we won't be able
    // to honor that.  What we can do, is switch to the original running
    // uid.  (setuid programs set euid, but leave ruid alone)
    if (geteuid != 0) {
        newuid = getuid();
        newgid = getgid();
    }

    if (setgid(newgid) < 0)
        boom("setup_child(setgid)");

    if (setuid(newuid) < 0) // As per man page, sets all
        boom("setup_child(setuid)");

    /* Call provilded function */
    if (fnptr != NULL) {
        fnptr(args);
    }

    /* And return to do normal work.   Or not.*/
    if (privmand_fd == -1)
        _exit(0);
}

void priv_sep_init(void (*servfn)(void),
    void (*childfn)(char * const *), char * const childfn_args[],
    const char *user, const char *root)
{
    int         sockfds[2];

    if (socketpair(AF_LOCAL, SOCK_STREAM, 0, sockfds) < 0)
        boom("socketpair");

    child_pid = fork();
    if (child_pid == 0) {
        wait_for_debugger();

        socketfun(sockfds, false);
        setup_child(childfn, childfn_args, user, root);
    } else if (child_pid < 0) {
        boom("fork");
    } else {
        /* Parent process */
        socketfun(sockfds, true);

        wait_for_debugger();

        if (servfn != NULL)
            servfn();
        /* Fall out.  If we even get here, we're actually a second
         * child.
         */
    }
}

void priv_init(const char *appname)
{
    /* Syslog init. */
    openlog("privman", LOG_PID, LOG_AUTHPRIV);

    /* Read the config now. */
    readConfig(appname);

    if (config == NULL) {
        fprintf(stderr,"No config.  Giving up.\n");
        abort();
    }

    priv_sep_init(privman_serv_init, 0, 0,
            config->unpriv_user.c_str(), config->unpriv_jail.c_str());

    /* If in the child, close the syslog() fd */
    if (child_pid > 0)
        closelog();
}


int priv_open(const char *pathname, int flags, ...)
{
    va_list             ap;/*va_start(pathname,ap);va_arg(ap,type);va_end(ap)*/
    message_t          *msg = msg_new();
    int                 n, retval;
    char                cwd[PATH_MAX];

    msg_init(msg, CMD_OPEN);

    msg_addInt(msg,flags);

    if (flags & O_CREAT) {
        va_start(ap, flags);
        msg_addInt(msg,va_arg(ap,int));
        va_end(ap);
    } else {
        msg_addInt(msg,0);
    }

    /* We have to canpath the path, else chdir() messes us up. */
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        /* Use a token "NFC" value.  we won't work right in this
         * case, but it might work if you didn't chdir
         */
        msg_addString(msg,"");
    } else {
        msg_addString(msg,cwd);
    }
    msg_addString(msg,pathname);
    /* send the message */
    n = msg_sendmsg(msg, privmand_fd);
    if (n < 0) {
        retval = -1;
        goto exit;
    }

    /* listen for responce */
    msg_clear(msg);
    n = msg_recvmsg(msg, privmand_fd);
    if ( n < 0 ) {
        retval = -1;
        goto exit;
    }

    n = msg_getInt(msg);
    if ( n < 0 ) {
        errno = -n;
        retval = -1;
    } else {
        retval = msg_getFd(msg);
    }
exit:
    msg_delete(msg);
    return retval;
}

/* Done in terms of fopen */
FILE* priv_fopen(const char *pathname, const char *mode)
{
    int         fd;
    int         open_mode = 0;

    /* First get the extra flags, then the basic open mode.  The
     * extra flags are purely depending on the base of the fopen
     * mode, while the base open mode is based on the + and the
     * base fopen mode.
     */
    switch(mode[0]) {
    case 'r':
        open_mode |= 0; /* Nothing here.  No creation. */       break;
    case 'w':
        open_mode |= O_CREAT|O_TRUNC;                           break;
    case 'a':
        open_mode |= O_CREAT|O_APPEND;                          break;
    default:
        errno = EINVAL;
        return NULL;
    }
    if (mode[1] == '+') /* '+' or '\0' */
        open_mode |= O_RDWR;
    else
        switch (mode[0]) {
        case 'w':
        case 'a':
            open_mode |= O_WRONLY;                              break;
        case 'r':
            open_mode |= O_RDONLY;                              break;
        }

    /* Punt to previously written code.  Easier. */
    fd = priv_open(pathname, open_mode);
    if (fd < 0)
        return NULL; /* errno should already be set */

   return fdopen(fd, mode);
}

int priv_unlink(const char *pathname)
{
    message_t          *msg = msg_new();
    int                 n, retval;
    char                cwd[PATH_MAX];

    msg_init(msg, CMD_UNLINK);

    /* We have to canpath the path, else chdir() messes us up. */
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        /* Use a token "NFC" value.  we won't work right in this
         * case, but it might work if you didn't chdir
         */
        msg_addString(msg,"");
    } else {
        msg_addString(msg,cwd);
    }
    msg_addString(msg,pathname);
    /* send the message */
    n = msg_sendmsg(msg, privmand_fd);
    if (n < 0) {
        retval = -1;
        goto exit;
    }

    /* listen for responce */
    msg_clear(msg);
    n = msg_recvmsg(msg, privmand_fd);
    if ( n < 0 ) {
        retval = -1;
        goto exit;
    }

    retval = msg_getInt(msg);
    if ( retval < 0 ) {
        errno = -n;
        retval = -1;
    }
exit:
    msg_delete(msg);
    return retval;
}
int priv_bind(int sockfd, struct sockaddr *addr, socklen_t addrlen)
{
    message_t  *msg = msg_new();
    int         n;

    msg_addInt(msg,CMD_BIND);
    msg_setFd(msg, sockfd);
    msg_addInt(msg, addrlen);
    msg_addData(msg, addr, addrlen);

    /* send the message */
    msg_sendmsg(msg, privmand_fd, "priv_bind(sendmsg)");

    /* listen for responce */
    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_bind(recvmsg)");
    n = msg_getInt(msg);
    if (n < 0) {
        errno = -n;
        n = -1;
    }

    msg_delete(msg);
    return n;
}

#ifdef HAVE_LIBPAM
int priv_pam_start(const char *service, const char *user,
                    const struct pam_conv *conv,
                    pam_handle_t **pamh_p)
{
    /* service: string.  Just send.
     * user: string.  Just send (two strings?  eek.  strlen:string
     * conversion function.  Don't bother with.  The other side will
     *  will have to return a call to us.  I think any of the priv_pam
     *  calls will have to listen for it.
     * pamh_p.  Er, I think we'll just pretend this is an opaque.  The
     *  other side will keep a list.
     */
    message_t          *msg = msg_new();
    int                 n, retval = PAM_SYSTEM_ERR;

    msg_addInt(msg, CMD_PAM_START);
    msg_addString(msg, service);
    msg_addString(msg, user);

    /* Save the conversion function for when we have to use it.
     * TBS: handle multiple man sessions/handles.
     */
    pam_types[PAM_CONV] = conv;

    msg_sendmsg(msg, privmand_fd, "priv_pam_start(sendmsg)");

    /* Listen for responce */
    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_pam_start(recvmsg)");

    n = msg_getInt(msg);
    if (n < 0) {
        errno = -retval;
        retval = PAM_PERM_DENIED;
    } else {
        assert( n == PRIV_PAM_RC );
        retval = msg_getInt(msg);
        *pamh_p = (pam_handle_t*)msg_getPtr(msg);
    }

    msg_delete(msg);
    return retval;
}

static int priv_pam_simple_func(pam_handle_t *pamh, int flags,
        const char *function_name, char function_code)
{
    message_t                  *msg = msg_new();
    int                         rc;
    enum privman_responces      cmd;

    msg_addInt(msg, function_code);
    msg_addPtr (msg, pamh);
    msg_addInt (msg, flags);

    /* send the message */
    msg_sendmsg(msg, privmand_fd, function_name);

    do {
        msg_clear(msg);
        msg_recvmsg(msg, privmand_fd, function_name);

        rc = msg_getInt(msg);
        if (rc < 0) {
            errno = -rc;
            msg_delete(msg);
            return PAM_PERM_DENIED;
        }

        cmd = (enum privman_responces)rc;
        switch (cmd) {
        case PRIV_PAM_RC:
            rc = msg_getInt(msg);
            break;
        case PRIV_PAM_RUN_CONV:
            handleConvert(msg);
            break;
        case PRIV_NONE:
        case PRIV_SET_COE:
        default:
            boom("priv_pam_simple_func(unexpected responce)");
            break;
        }
    } while (cmd != PRIV_PAM_RC);

    msg_delete(msg);
    return rc;
}

#define PRIV_PAM_SIMPLE(name,code)                              \
int priv_##name (pam_handle_t *pamh, int flags)                 \
{                                                               \
    return priv_pam_simple_func(pamh, flags,                    \
            __FUNCTION__, code) ;                               \
}

#define PRIV_PAM_SIMPLE2(name,code)                             \
int priv_##name (pam_handle_t *pamh, unsigned int flags)        \
{                                                               \
    return priv_pam_simple_func(pamh, flags,                    \
            __FUNCTION__, code) ;                               \
}


PRIV_PAM_SIMPLE(pam_authenticate,       CMD_PAM_AUTHENTICATE)
PRIV_PAM_SIMPLE(pam_acct_mgmt,          CMD_PAM_ACCT_MGMT)
PRIV_PAM_SIMPLE(pam_end,                CMD_PAM_END)
PRIV_PAM_SIMPLE(pam_setcred,            CMD_PAM_SETCRED)
PRIV_PAM_SIMPLE(pam_chauthtok,          CMD_PAM_CHAUTHTOK)
PRIV_PAM_SIMPLE(pam_open_session,       CMD_PAM_OPEN_SESSION)
PRIV_PAM_SIMPLE(pam_close_session,      CMD_PAM_CLOSE_SESSION)
#ifdef LO_HAVE_PAM_FAIL_DELAY
PRIV_PAM_SIMPLE2(pam_fail_delay,        CMD_PAM_FAIL_DELAY)
#endif

int priv_pam_set_item(pam_handle_t *pamh, int item_type, const void *item)
{
    message_t          *msg = NULL;
    int                 rc;

    assert(item_type != PAM_CONV); /* handled by pam_start */
    /* Assume that pam_fail_delay is not dynamically loaded. */

    msg = msg_new();
    msg_addInt(msg, CMD_PAM_SET_ITEM);
    msg_addPtr (msg, pamh);
    msg_addInt (msg, item_type);
    if (item_type != PAM_FAIL_DELAY) {
        msg_addString(msg, (char *)item);
    } else {
        msg_addPtr(msg, item);
    }

    /* send the message */
    msg_sendmsg(msg, privmand_fd, "priv_pam_set_item(sendmsg)");

    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_pam_set_item(recvmsg)");

    rc = msg_getInt(msg); /* were we denied at the gate? */
    if (rc < 0) {
        errno = -rc;
        msg_delete(msg);
        return PAM_PERM_DENIED;
    }

    assert((enum privman_responces)rc == PRIV_PAM_RC);

    rc = msg_getInt(msg); /* and the RC of pam_set_item. */

    /* Wait until success to set the cache. */
    if (rc == PAM_SUCCESS) {
        if (item_type != PAM_FAIL_DELAY) {
            if (pam_types[item_type])
                free(((void*)pam_types[item_type]));
            pam_types[item_type] = strdup((char *)item);
        } else {
            /* FAIL_DELAY */
            pam_types[item_type] = item;
        }
    }

    msg_delete(msg);
    return rc;
}

int priv_pam_get_item(pam_handle_t *pamh, int item_type, const void **item)
{
    message_t          *msg = NULL;
    int                 rc;

    if (pam_types[item_type] != NULL) {
        *item = pam_types[item_type];
        return PAM_SUCCESS;
    }

    assert(item_type != PAM_CONV); /* handled by pam_start */
    /* Assume that pam_fail_delay is not dynamically loaded. */

    msg = msg_new();
    msg_addInt(msg, CMD_PAM_GET_ITEM);
    msg_addPtr (msg, pamh);
    msg_addInt (msg, item_type);

    /* send the message */
    msg_sendmsg(msg, privmand_fd, "priv_pam_get_item(sendmsg)");

    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_pam_get_item(recvmsg)");

    rc = (enum privman_responces)msg_getInt(msg);
    if (rc < 0) {
        errno = -rc;
        msg_delete(msg);
        return PAM_PERM_DENIED;
    }
    assert((enum privman_responces)rc == PRIV_PAM_RC);

    rc = msg_getInt(msg);

    if (rc == PAM_SUCCESS) {
        if (item_type == PAM_FAIL_DELAY) {
            pam_types[item_type] = msg_getPtr(msg);
        } else {
#define ITEM_BUF_SIZE 1024
            pam_types[item_type] = malloc(ITEM_BUF_SIZE);
            msg_getString(msg, (char*)(pam_types[item_type]),ITEM_BUF_SIZE-1);
            pam_types[ITEM_BUF_SIZE-1] = '\0';
        }

        *item = pam_types[item_type];
    }
    msg_delete(msg);
    return rc;
}

int priv_pam_putenv(pam_handle_t *pamh, const char *name_value);
int priv_pam_getenv(pam_handle_t *pamh, const char *name);
/*
PAM:

    To do these right, I need a "map" implimentation.  I'm seriously
    thinking of redoing this in C++ with a C interface, so when I do
    that I'll do these function.

    pam_putenv(pam_handle, "FOO=bar"); "FOO=" for empty, "FOO" to nuke
    pam_getenv(pam_handle, "FOO")
    pam_getenvlist(pam_handle)

*/
#endif /* HAVE_LIBPAM */

pid_t priv_fork(void)
{
    /* Tell the parent to dup.  Parent will fork, and will return the
     * fd we now use to talk to it.
     * We fork, tell parent our new pid.
     * No race condition since parent is ST.  I think
     * XXX Race condition?
     */
    pid_t       retval;
    int         new_fd, n;
    message_t  *msg = msg_new();

    msg_init(msg, CMD_FORK);
    n = msg_sendmsg(msg, privmand_fd);
    if (n < 0) {
        retval = -1;
        goto exit;
    }

    msg_clear(msg);
    n = msg_recvmsg(msg, privmand_fd);
    if (n < 0) {
        retval = -1;
        goto exit;
    }

    n = msg_getInt(msg);
    if (n < 0) {
        errno = -n;
        retval = -1;
        goto exit;
    } else {
        new_fd = msg_getFd(msg);
    }

    retval = fork();
    if (retval > 0) {
        /* Parent */
        close(new_fd); /* don't need it here */
    } else if (retval == 0) {
        /* Child */
        close(privmand_fd);
        privmand_fd = new_fd;
    } else {
        /* error.  Tell new server.*/
        msg_init(msg, CMD_EXIT);
        msg_addInt(msg, -1);
        msg_sendmsg(msg, new_fd); /* Never check an error you can't handle */
        close(new_fd);
    }

exit:
    msg_delete(msg);
    return retval;
}

/* "daemon".  On the client side, this does some muching with FD's.
 * On the server side, it does a fork();exit() pair in the original
 * process so that it detacches.
 */

int priv_daemon(int nochdir, int noclose)
{
    message_t  *msg = msg_new();
    int         n = 0;

    /* First, tell parent to detach */
    msg_init(msg, CMD_DAEMON);
    msg_sendmsg(msg, privmand_fd, "priv_daemon(sendmsg)");

    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_daemon(sendmsg)");

    n = msg_getInt(msg);
    msg_delete(msg);

    if (n < 0) {
        errno = -n;
        return -1;
    }

#ifdef HAVE_SETSID
    n = setsid();
    if (n < 0)
        return n;
    /* Can't fail, as priv_init() makes us a child */
#endif
    if (!nochdir)
        chdir("/");

    if (!noclose) {
        freopen("/dev/null", "r", stdin);
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "a", stderr);
    }

    return 0;
}

/* Exec "filename" as user "user" in chroot jail "root" with args argv,
 * and environment envp
 * TODO: limits.  Feh.
 *
 * filename as found from the root jail.
 * Will be executed with as user, so check permissions.
 *
 * Actually Executes from the parent, then exit's here.
 * priv_rerunas(), with function pointer that demarshalls args, 
 * tells the monitor to quit, and exec's.
 */
static void priv_execve_impl(char * const arg[]);
int priv_execve(const char *filename, char * const argv[], char * const envp[],
            const char *user, const char *root)
{
    const char**arg;
    int         i, j, argc, envc;
    char        buf[5]; /* "9999\0" */

    for (argc = 0; argv[argc] != NULL && argc < 9999; ++argc)
        ;
    for (envc = 0; envp[envc] != NULL && envc < 9999; ++envc)
        ;

    /* arg = { path + "3" + argv[0 .. 2] + "2" + envp[0 .. 1] + 0}; */
    arg = (const char **)malloc(sizeof(char *) * (argc + envc + 2 + 1 + 1));

    i = 0;
    arg[i++] = filename;

    snprintf(buf, sizeof(buf)-1, "%d", argc); buf[sizeof(buf)-1] = '\0';
    arg[i++] = strdup(buf);

    for ( j = i ; i < argc + j; ++i) {
        arg[i] = argv[i-j];
    }

    snprintf(buf, sizeof(buf)-1, "%d", envc); buf[sizeof(buf)-1] = '\0';
    arg[i++] = strdup(buf);

    for ( j = i ; i < envc + j; ++i) {
        arg[i] = envp[i-j];
    }
    arg[i] = NULL;

    i = priv_rerunas(priv_execve_impl, (char * const *)arg, user, root, 0);

    if (i < 0) {
        free(arg);
        return i;
    }
    /* The exec should happen in the new slave.  We want the monitor
     * to wait on the new child to exit so that it appears to exit when
     * the new child does.
     */
    _exit(0);
}

static void priv_execve_impl(char * const arg[])
{
    const char         *filename;
    char              **argv;
    char              **envp;
    int                 argc, envc, i, j;

    /* Tell the monitor to exit */
    priv_exit(0);

    i = 0;
    filename = arg[i++];

    argc = atoi(arg[i++]);
    argv = (char**)malloc(sizeof(char*) * (argc + 1));
    for (j = 0; j < argc; ++j) {
        argv[j] = arg[i++];
    }
    argv[j] = NULL;

    envc = atoi(arg[i++]);
    envp = (char**)malloc(sizeof(char*) * (envc + 1));
    for (j = 0; j < envc; ++j) {
        envp[j] = arg[i++];
    }
    envp[j] = NULL;

    execve(filename, argv, envp);
    perror("priv_execve_impl(execve)");
    _exit(EXIT_FAILURE);
}

/* Creates a clean fork() from the privmand server with state equivilent
 * to the client state when priv_init() was first called.
 *
 * Invokes the specified function, with the string arg provided.
 * chroots to the directory provided, setuid's to the user provided.
 * TODO: limits.  Feh.
 *
 */
int priv_rerunas(void (*fnptr)(char * const *), char * const arg[],
            const char *user, const char *root, int flags)
{
    int i;
    message_t *msg = msg_new();

    msg_init(msg, CMD_RERUN_AS);
    msg_addInt(msg, flags);
    msg_addPtr(msg, (void*)fnptr);
    msg_addArgv(msg, arg);
    msg_addString(msg, user != NULL ? user : "");
    msg_addString(msg, root != NULL ? root : "");

    /* send the message */
    msg_sendmsg(msg, privmand_fd, "priv_rerunas(sendmsg)");

    /* listen for responce */
    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_rerunas(recvmsg)");
    i = msg_getInt(msg);
    if (i < 0) {
        errno = -i;
        i = -1;
    } else if (!(flags & PRIV_RR_OLD_SLAVE_MONITORED)) {
        /* the "real program" transitioned to the new one. */
        close(privmand_fd);
    }

    msg_delete(msg);
    return i;
}

/* Creates a clean fork() from a new privmand server with state equivilent
 * to the client state when priv_init() was first called.
 *
 * Invokes the specified function, with the string arg provided.
 * chroots to the directory provided, setuid's to the user provided.
 * TODO: limits.  Feh.
 *
 */
int priv_respawn_as(void (*fnptr)(char * const *), char * const arg[],
            const char *user, const char *root)
{
    message_t *msg = msg_new();
    int i;

    msg_init(msg, CMD_RESPAWN_AS);
    msg_addPtr(msg, (void*)fnptr);
    msg_addArgv(msg, arg);
    msg_addString(msg, user != NULL ? user : "");
    msg_addString(msg, root != NULL ? root : "");

    /* send the message */
    msg_sendmsg(msg, privmand_fd, "priv_respawn_as(sendmsg)");

    /* listen for responce */
    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_respawn_as(recvmsg)");
    i = msg_getInt(msg);
    if (i < 0) {
        errno = -i;
        i = -1;
    }

    msg_delete(msg);
    return i;
}
/* Proxies wait4.  Nothing is really privileged about this call, but
 * due to the way rerunas et. all work, sometimes the wait has to be
 * done from the monitor.
 */
pid_t	priv_wait4(pid_t pid, int *status, int options, struct rusage *rus)
{
    message_t  *msg = msg_new();
    pid_t       retval;
    int         flags = 0;

    if (status != NULL)
        flags |= WANTS_STATUS;
    if (rus    != NULL)
        flags |= WANTS_RUSAGE;

    msg_init(msg, CMD_WAIT4);

    msg_addInt(msg, pid);
    msg_addInt(msg, options);
    msg_addInt(msg, flags);

    msg_sendmsg(msg, privmand_fd, "priv_wait4(sendmsg)");
    msg_clear(msg);

    msg_recvmsg(msg, privmand_fd, "priv_wait4(recvmsg)");

    retval = msg_getInt(msg);

    if (retval < 0) {
        errno = -retval;
        retval = -1;
    } else {
        if (status != NULL)
            *status = msg_getInt(msg);
        if (rus    != NULL)
            msg_getData(msg, rus, sizeof(*rus));
    }

    msg_delete(msg);
    return retval;
}


static std::map<int, int> fd_handle_map; /* map fd to popen handle */

FILE*   priv_popen_as(const char *command, const char *type, const char *user)
{
    message_t  *msg = msg_new();
    FILE       *retval;
    int         fd;
    int         rc;

    /* Stupid checks */
    if (command == NULL || type == NULL || type[1] != '\0' ||
            (type[0] != 'r' && type[0] != 'w')) {
        errno = EINVAL;
        return NULL;
    }
    msg_init(msg, CMD_POPEN);

    msg_addString(msg, command);
    if (type[1] == 'r') {
        msg_addInt(msg, 0);
    } else {
        msg_addInt(msg, 1);
    }
    msg_addString(msg, user);
    msg_addString(msg, "/");

    msg_sendmsg(msg, privmand_fd, "priv_popen(sendmsg)");
    msg_clear(msg);

    msg_recvmsg(msg, privmand_fd, "priv_popen(recvmsg)");

    rc = msg_getInt(msg);

    if (rc < 0) {
        errno = -rc;
        retval = NULL;
    } else {
        fd = msg_getFd(msg);
        retval = fdopen(fd, type);
        fd_handle_map[fd] = rc;
    }

    msg_delete(msg);
    return retval;
}

int     priv_pclose(FILE *stream)
{
    message_t  *msg;
    int         rc;
    int         fd = fileno(stream);
    int         handle;

    /* Stupid check */
    if (fd_handle_map.count(fd) == 0)
        return -1; /* EINVAL */

    handle = fd_handle_map[fd];
    /* Close the stream, maybe causing the other side to keel over. */
    fd_handle_map.erase(fd);
    pclose(stream);

    msg = msg_new();
    msg_init(msg, CMD_PCLOSE);
    msg_addInt(msg, handle);
    msg_sendmsg(msg, privmand_fd, "priv_pclose(sendmsg)");

    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_pclose(recvmsg)");

    rc = msg_getInt(msg);

    if (rc < 0) {
        errno = -rc;
        rc = -1;
    }

    msg_delete(msg);
    return rc;
}

/*
 * Extension framework. 
 */

info_fn_map_t info_fn_map;
 cap_fn_map_t  cap_fn_map;

/* Prevent the same handle from being in both maps. */
static int handle_counter = 0;

int priv_register_info_fn(char *(*fnptr)(char * const *))
{
    int handle;
 
    /* Must be done before the call to priv_init() */
    if (geteuid() != 0 && geteuid() == getuid()) {
        errno = EPERM;
        return -1;
    }

    handle = handle_counter++;

    info_fn_map[handle] = fnptr;
    return handle;
}

int priv_register_cap_fn(int (*fnptr)(char * const *))
{
    int handle;
 
    /* Must be done before the call to priv_init() */
    if (geteuid() != 0 && geteuid() == getuid()) {
        errno = EPERM;
        return -1;
    }

    handle = handle_counter++;

    cap_fn_map[handle] = fnptr;
    return handle;
}


char *priv_invoke_info_fn(int handle, char * const args[])
{
    message_t  *msg = msg_new();
    char       *retval;
    int         rc;

    msg_init(msg, CMD_CUSTOM_INFO);

    msg_addInt(msg, handle);
    msg_addArgv(msg, args);

    /* send request */
    msg_sendmsg(msg, privmand_fd, "priv_invoke_info_fn(sendmsg)");
    /* listen for responce */
    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_invoke_info_fn(recvmsg)");

    rc = msg_getInt(msg);
    if (rc < 0) {
        errno = -rc;
        retval = NULL;
    } else {
        retval = msg_getAllocStr(msg, 4096);
    }
    msg_delete(msg);
    return retval;
}

int priv_invoke_cap_fn(int handle, char * const args[])
{
    message_t  *msg = msg_new();
    int         rc;

    msg_init(msg, CMD_CUSTOM_CAP);

    msg_addInt(msg, handle);
    msg_addArgv(msg, args);

    /* send request */
    msg_sendmsg(msg, privmand_fd, "priv_invoke_cap_fn(sendmsg)");
    /* listen for responce */
    msg_clear(msg);
    msg_recvmsg(msg, privmand_fd, "priv_invoke_cap_fn(recvmsg)");

    rc = msg_getInt(msg);
    if (rc < 0) {
        errno = -rc;
        rc = -1;
    } else {
        rc = msg_getFd(msg);
    }
    msg_delete(msg);
    return rc;
}

/* Doesn't exit, just causes the privman server to. */
void priv_exit(int status)
{
    message_t  *msg;

    msg = msg_new();

    msg_init(msg, CMD_EXIT);
    msg_addInt(msg, status);
    msg_sendmsg(msg, privmand_fd); /* Never check an error you can't handle */
    close(privmand_fd);
}


