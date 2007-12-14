%{
/* 
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * $Id: config_lex.ll,v 1.11 2002/11/12 04:43:50 dougk Exp $
 */

#define token(c)   { return(c); }
#include <string.h>
#include <syslog.h>

#include "types.h"
    /* the types used by the lexer. */

#include "config_parse.h"
    /* The token definitions */

static void priv_config_count(void);
%}

ID      [/_a-zA-Z][a-zA-Z0-9_\-/\.]*
NUM     [0-9]*
PATHELM [^/ \t\n*]+
PATHSEP [/]

PATH    {PATHSEP}({PATHELM}{PATHSEP})*({PATHELM}|[*])

BOOLEAN true|false|TRUE|FALSE

%%

#.*$          	{ /* comment */ priv_config_count(); }

bind            {       priv_config_count(); return(K_BIND);                 }
open_ro         {       priv_config_count(); return(K_OPEN_RO);              }
open_rw         {       priv_config_count(); return(K_OPEN_RW);              }
open_ao         {       priv_config_count(); return(K_OPEN_AO);              }
unlink		{       priv_config_count(); return(K_UNLINK);               }

auth            {       priv_config_count(); return(K_AUTH);                 }
fork            {       priv_config_count(); return(K_FORK);                 }
runas           {       priv_config_count(); return(K_RUNAS);                }
allow_rerun	{       priv_config_count(); return(K_ALLOW_RERUN);          }
unpriv_user	{	priv_config_count(); return(K_UNPRIV_USER);	     }
chroot		{	priv_config_count(); return(K_CHROOT);	     	     }
auth_allow_rerun {	priv_config_count(); return(K_AUTH_ALLOW_RERUN);     }


{NUM}		{       yylval.num = atoi(yytext);
                        priv_config_count(); return NUM;
		}

{PATH}          {       yylval.s = strdup(yytext);
                        priv_config_count(); return PATH;
                }

{BOOLEAN}       {
                        /* Regex matched, so its only one of
                         * "true|false|TRUE|FALSE|1|0"
                         */
                        if ( yytext[0] == 't' || yytext[0] == 'T'
                                || yytext[0] == '1' )
                            yylval.b = true;
                        else
                            yylval.b = false;
                        priv_config_count(); return BOOLEAN;
                }

{ID}            {       yylval.s = strdup(yytext);
                        priv_config_count(); return ID;
                }

[{}*]           { priv_config_count(); return yytext[0];        }

[ \t\n]		{ priv_config_count(); }

.               { priv_config_count(); }

<<EOF>>		{	yyterminate(); }

%%

static unsigned int column = 0;
static char lastline[2048] = {0}, thisline[2048] = {0};
static int lineno = 0;

static void priv_config_count(void)
{
    unsigned int i;
    for (i = 0; yytext[i] != '\0' && column < (sizeof(thisline) - 2); ++i) {
        if (yytext[i] == '\n') {
            thisline[column++] = '\n';
            thisline[column++] = '\0';
            strncpy(lastline, thisline, column); /* Move it into lastline */
            memset(thisline,0,sizeof(thisline));
            column = 0;
            ++lineno;
        } else if (yytext[i] == '\t') {
            int width = 8 - (column % 8);
            strncpy(thisline + column, "        ", width);
            column += width;
        } else {
            thisline[column++] = yytext[i];
        }
    }
}

void yyerror(const char *msg)
{
    thisline[column+1] = 0;
    syslog(LOG_ERR, "%s%s",lastline, thisline);
    syslog(LOG_ERR, "\n%*s\n%s at line %d\n", column, "^", msg, lineno);
}

