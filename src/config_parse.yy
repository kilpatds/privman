%{
/* 
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * $Id: config_parse.yy,v 1.17 2002/11/12 04:43:50 dougk Exp $
 *
 */

#include "../config.h"
#include <string.h>
/* memset */
#include <stdio.h>
/* perror */
#include <unistd.h>
/* exit() */
#include <netdb.h>
/* getservbyname */

/* ntohs */
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* getpwnam */
#include <pwd.h>

#include "types.h"

extern config_t *config;
void yyerror(const char *msg);

#ifndef YYERROR_VERBOSE
#define YYERROR_VERBOSE 1
#endif
%}

%union {
    int         num;
    bool        b;
    char       *s;

    path_list  *pathlist;
    user_list  *userlist;
    port_list  *portlist;

    config_t   *config;
}

%token  <num>           NUM
%token  <b>             BOOLEAN
%token  <s>             ID

%token  <s>             PATH

%token                  K_BIND K_OPEN_RO K_OPEN_RW K_OPEN_AO K_UNLINK
%token                  K_AUTH K_RUNAS K_FORK K_AUTH_ALLOW_RERUN
%token                  K_UNPRIV_USER K_CHROOT K_ALLOW_RERUN

%type   <pathlist>      pathlist
%type   <portlist>      bind_stmt portlist
%type	<num>		port
%type   <userlist>      runas_stmt userlist
%type   <b>             auth_stmt fork_stmt rerunas_stmt auth_allow_rerunas_stmt
%type   <config>        config_stmt_list
%type   <pathlist>      open_ro_stmt open_rw_stmt open_ao_stmt
%type   <pathlist>      unlink_stmt
%type	<s>		unpriv_user_stmt chroot_jail_stmt user


%%


config:                 config_stmt_list
                    {
                        config = $1;
                    }
            ;

config_stmt_list:       config_stmt_list bind_stmt
                            {   $1->bind_port.insert($2->begin(),$2->end());
                                $$=$1; delete $2; }
            |           config_stmt_list open_ro_stmt
                            {   $1->open_ro.insert($2->begin(),$2->end());
                                $$=$1; delete $2; }
            |           config_stmt_list open_rw_stmt
                            {   $1->open_rw.insert($2->begin(),$2->end());
                                $$=$1; delete $2; }
            |           config_stmt_list open_ao_stmt
                            {   $1->open_ao.insert($2->begin(),$2->end());
                                $$=$1; delete $2; }
            |           config_stmt_list unlink_stmt
                            {   $1->unlink.insert($2->begin(),$2->end());
                                $$=$1; delete $2; }
            |           config_stmt_list auth_stmt
                            {   $1->auth = $2; $$=$1; }
            |           config_stmt_list fork_stmt
                            {   $1->pfork = $2; $$=$1; }
	    |		config_stmt_list rerunas_stmt
			    {   $1->rerunas = $2;  $$ = $1; }
	    |		config_stmt_list auth_allow_rerunas_stmt
			    {	$1->auth_allow_rerun = $2; $$ = $1; }
            |           config_stmt_list runas_stmt
                            {   $1->user.insert($2->begin(),$2->end());
                                $$ = $1; delete $2; }
	    |		config_stmt_list unpriv_user_stmt
			    {   if ($1->unpriv_user != "") {
				    yyerror("Duplicate unprivuser entries.");
				    YYERROR;
                               }
				$1->unpriv_user = $2;  $$ = $1; }
	    |		config_stmt_list chroot_jail_stmt
			    {   if ($1->unpriv_jail != "") {
				    yyerror("Duplicate jail entries.");
				    YYERROR;
				}
				$1->unpriv_jail = $2;  $$ = $1; }
	    |		config_stmt_list error
			    { $$ = $1; }
            |
                            { $$ = new config_t; }
            ;

bind_stmt:              K_BIND port { $$ = new port_list; $$->insert($2); }
	    |		K_BIND '{' portlist '}'		{ $$ = $3; }
            ;

open_ro_stmt:           K_OPEN_RO '{' pathlist '}'      { $$ = $3; }
            ;

open_rw_stmt:           K_OPEN_RW '{' pathlist '}'      { $$ = $3; }
            ;

open_ao_stmt:           K_OPEN_AO '{' pathlist '}'      { $$ = $3; }
            ;

unlink_stmt:            K_UNLINK  '{' pathlist '}'      { $$ = $3; }
            ;

auth_stmt:              K_AUTH BOOLEAN          { $$ = $2; }
            |           K_AUTH NUM
                            {
                                switch ($2) {
                                case 0: $$ = false; break;
                                case 1: $$ = true;  break;
                                default:
			            yyerror("Syntax error: not boolean");
			            YYERROR;
                                }
                            }
            ;

fork_stmt:              K_FORK BOOLEAN          { $$ = $2; }
            |           K_FORK NUM
                            {
                                switch ($2) {
                                case 0: $$ = false; break;
                                case 1: $$ = true;  break;
                                default:
			            yyerror("Syntax error: not boolean");
			            YYERROR;
                                }
                            }
            ;

rerunas_stmt:		K_ALLOW_RERUN BOOLEAN	{ $$ = $2; }
	    ;

auth_allow_rerunas_stmt: K_AUTH_ALLOW_RERUN BOOLEAN	{ $$ = $2; }
	    ;

runas_stmt:             K_RUNAS user    { $$ = new user_list; $$->insert($2); }
	    |		K_RUNAS '{' userlist '}' 	{ $$ = $3; }
            ;

unpriv_user_stmt:	K_UNPRIV_USER ID
		    { $$ = $2; }
	    ;

chroot_jail_stmt:	K_CHROOT PATH
		    { $$ = $2; }
	    ;

pathlist:       PATH pathlist
                    { $$ = $2;            $$->insert($1);}
            |
                    { $$ = new path_list; }
            ;

portlist:	port portlist
		    { $$ = $2;		  $$->insert($1);}
	    |
		    { $$ = new port_list; }
	    ;

port:		NUM 	{ $$ = $1; }
	    |  '*'	{ $$ = 0;  }
	    |  ID	{
                            /* use getservbyname to get a ## from the
                             * port.  It not listed, yyerror.
                             */
                            servent    *s;
                            s = getservbyname($1, "tcp");
                            if (s) {
                                $$ = ntohs(s->s_port);
                            } else {
                                yyerror("Unknown port");
                                YYERROR;
                            }
			}
	    ;

userlist:	user userlist
			{ $$ = $2;	$$->insert($1);}
	    |
			{ $$ = new user_list; }
	    ;

user:		ID	{
			    if (getpwnam($1) == NULL) {
			        yyerror("Unknown user");
			        YYERROR;
			    } else {
			        $$ = $1;
                            }
			}
	    |   '*'	{ $$ = "*"; }
	    ;

%%

extern "C" {
    int yywrap(void);
}

int yywrap(void)
{
    return 1; /* we redefined yyin, so return 1. */
}

