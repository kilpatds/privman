/*
 * Copyright © 2002  Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * types.h: Implimentation header.  Contains certain C++ types used
 * by the configuration parser and associated code.
 *
 * $Id: types.h,v 1.16 2002/11/12 04:43:51 dougk Exp $
 */
#ifndef MY_TYPES_H
#define MY_TYPES_H 1

#ifdef __cplusplus
/* Can I have STL?  Please? */
#include <set>
#include <string>

typedef std::set<std::string, std::less<std::string> >  path_list;
typedef std::set<std::string, std::less<std::string> >  user_list;
typedef std::set<int,         std::less<int> >          port_list;

struct config_t {
    path_list   open_ro;        /* read-only files              */
    path_list   open_rw;        /* read-write files             */
    path_list   open_ao;        /* append-only files            */
    path_list   unlink;         /* Files which can be unlinked  */

    user_list   user;           /* run as users.                */

    std::string unpriv_user;    /* Unpriviledged user           */
    std::string unpriv_jail;    /* chroot jail                  */

    bool        auth;           /* allowed to use PAM?          */
    bool        auth_allow_rerun;/* allowed to rerunas any authenticated user*/
    bool        pfork;          /* allowed to fork and keep priv*/
    bool        rerunas;        /* allowed to rerun as a user   */
    port_list   bind_port;      /* ports allowed to bind to     */
};
#else
typedef struct config_t config_t;
#endif

/* Long list of #define's to prevent our lexer from killing other
 * lexers (or vice-versa)
 */
#define yymaxdepth      privparse_maxdepth
#define yyparse         privparse_parse
#define yylex           privparse_lex
#define yyerror         privparse_error
#define yylval          privparse_lval
#define yychar          privparse_char
#define yydebug         privparse_debug
#define yypact          privparse_pact
#define yyr1            privparse_r1
#define yyr2            privparse_r2
#define yydef           privparse_def
#define yychk           privparse_chk
#define yypgo           privparse_pgo
#define yyact           privparse_act
#define yyexca          privparse_exca
#define yyerrflag       privparse_errflag
#define yynerrs         privparse_nerrs
#define yyps            privparse_ps
#define yypv            privparse_pv
#define yys             privparse_s
#define yy_yys          privparse_yys
#define yystate         privparse_state
#define yytmp           privparse_tmp
#define yyv             privparse_v
#define yy_yyv          privparse_yyv
#define yyval           privparse_val
#define yylloc          privparse_lloc
#define yyreds          privparse_reds
#define yytoks          privparse_toks
#define yylhs           privparse_yylhs
#define yylen           privparse_yylen
#define yydefred        privparse_yydefred
#define yydgoto         privparse_yydgoto
#define yysindex        privparse_yysindex
#define yyrindex        privparse_yyrindex
#define yygindex        privparse_yygindex
#define yytable         privparse_yytable
#define yycheck         privparse_yycheck
#define yyname          privparse_yyname
#define yyrule          privparse_yyrule

#ifdef __cplusplus
/*  define the linkage here so the generated YACC files have
 *  the correct linkage.
 */
extern "C" {
#endif
    int yylex(void);
    int yyparse(void);
    void yyerror(const char *);
#ifdef __cplusplus
}
#endif
#endif

