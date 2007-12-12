/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * priv_impl.h
 * Header file for the implimentation bits of privman.  Things common
 * between the server and the client halves.
 *
 * $Id: priv_impl.h,v 1.22 2003/04/10 00:25:52 dougk Exp $
 */


/* Global variables */

extern int              privmand_fd;

extern pid_t            child_pid;

extern config_t        *config;

/* The first byte of a command message.  What is this command? */
enum commands {
    CMD_OPEN                    = 'o',
    CMD_UNLINK                  = 'u',
    CMD_BIND                    = 'b',

    CMD_PAM_START               = 'p',
    CMD_PAM_AUTHENTICATE        = 'a',
    CMD_PAM_ACCT_MGMT           = 'm',
    CMD_PAM_END                 = 'P',
    CMD_PAM_SETCRED		= 'c',
    CMD_PAM_OPEN_SESSION        = 's',
    CMD_PAM_CLOSE_SESSION       = 'S',
    CMD_PAM_GET_ITEM            = 'i',
    CMD_PAM_SET_ITEM            = 'I',
    CMD_PAM_GETENV              = 'e',
    CMD_PAM_PUTENV              = 'E',
    CMD_PAM_CHAUTHTOK           = 't',
    CMD_PAM_FAIL_DELAY          = 'D',

    CMD_FORK                    = 'f',
    CMD_EXIT                    = 'x',  /* This process going away. */
    CMD_DAEMON                  = 'd',
    CMD_WAIT4                   = '4',

    CMD_POPEN                   = 'k',
    CMD_PCLOSE                  = 'K',

    CMD_RERUN_AS                = 'R',
    CMD_RESPAWN_AS              = 'r',

    CMD_CUSTOM_INFO             = 'n',
    CMD_CUSTOM_CAP              = 'C'
};

/* Virtual structure of the command message:
 * {
 *      int             command;
 *      byte            command_specific_data[];
 * }
 *
 * Virtual structure of the repsonce:
 * {
 *     int              privman_rc;
 *                      // < 0, errno = -privman_rc; return -1;
 *                      // > 0, command_specific return (PAM mostly)
 *                      // = 0, success.
 *     byte             command_specific_data[];
 * }
 */

/* Convience message functions to help with this:
 */

static __inline__ 
void msg_init(message_t *msg, enum commands cmd) {
    msg_clear(msg);
    msg_addInt(msg, cmd);
}

static __inline__ 
void msg_initResponce(message_t *msg, int rc) {
    msg_clear(msg);
    msg_addInt(msg, rc);
}


/* Factor out some of the common error handling */
static __inline__ void boom(const char *where) __attribute((__noreturn__));
static __inline__ void boom(const char *where)
{
    syslog(LOG_ERR, "%s: %m", where);
    /* Only one of the two processes should exit().  The other should
     * _exit().  To allow atexit() et. all to work for the client
     * processes, the parent will use _exit().
     */
    if (child_pid == 0)
        exit(-1);
    else
        _exit(-1);
}

static __inline__
void msg_recvmsg(message_t *msg, int fd, const char *boommsg) {
    int n = msg_recvmsg(msg, fd);
    if (n < 0)
        boom(boommsg);
}

static __inline__
void msg_sendmsg(message_t *msg, int fd, const char *boommsg) {
    int n = msg_sendmsg(msg, fd);
    if (n < 0)
        boom(boommsg);
}

static __inline__
void msg_addArgv(message_t *msg, char * const argv[]) {
    int i;
    for (i = 0; argv != NULL && argv[i] != NULL; ++i)
        ;
    msg_addInt(msg, i);
    for (i = 0; argv != NULL && argv[i] != NULL; ++i)
        msg_addString(msg, argv[i]);
}

static __inline__
char ** msg_getArgv(message_t *msg) {
    char **retval;
    int i;
    int argc;
   
    argc = msg_getInt(msg);
    retval = (char**)malloc(sizeof(char*) * (argc+1));

    for (i = 0; i < argc ; ++i) {
        if ((retval[i] = msg_getAllocStr(msg, 4096)) == NULL)
            boom("msg_getArgv, bad arg string");
    }
    retval[i] = NULL; /* Null terminate the array */

    return retval;
}



/* Codes for messages back to the client.  Do you need to run the
 * conversion function?
 */
enum privman_responces {
    PRIV_NONE           = 0, /* Nothing to do here.             */
    PRIV_PAM_RC         = 1, /* Standard Pam return code        */
    PRIV_PAM_RUN_CONV,       /* Run the PAM conversion function */

    PRIV_SET_COE             /* Set Close-on-exec               */
};

/* The server control function */
void privman_serv_init(void);

void priv_sep_init(void (*servfn)(void),
        void (*childfn)(char * const*), char *const childfn_arg[],
        const char *user, const char *root);

void setup_child(void (*fnptr)(char * const *), char * const args[],
        const char *user, const char *root);

/* Defines for wait4.  Wait4 has three possible output values, 
 * the return value, which is always used, int *status, and
 * rusage *rusage.  Lets only ask for the last two if the caller
 * cares.
 */
#define WANTS_STATUS    1
#define WANTS_RUSAGE    2

#ifdef __cplusplus
/* The maps that hold custom methods.  Typedefed for iterator reasons. */
typedef std::map<int,char *(*)(char * const *)> info_fn_map_t;
typedef std::map<int,int   (*)(char * const *)>  cap_fn_map_t;

extern info_fn_map_t info_fn_map;
extern  cap_fn_map_t  cap_fn_map;
#endif

