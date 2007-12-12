dnl test for "socklen_t" type.
dnl if it doesn't exist, #define socklen_t size_t
AC_DEFUN([AC_TYPE_SOCKLEN_T], [
	AC_REQUIRE([AC_STDC_HEADERS])dnl
	AC_MSG_CHECKING(for socklen_t)
	AC_CACHE_VAL(ac_cv_type_socklen_t,
		[AC_EGREP_CPP(dnl
changequote(<<,>>)dnl
<<(^|[^a-zA-Z_0-9])socklen_t[^a-zA-Z_0-9]>>dnl
changequote([,]), [#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#include <sys/socket.h>
], ac_cv_type_socklen_t=yes, ac_cv_type_socklen_t=no)])dnl
	AC_MSG_RESULT($ac_cv_type_socklen_t)
	if test $ac_cv_type_socklen_t = no; then
		AC_DEFINE(socklen_t, size_t,
		[Define to 'size_t' if <sys/socket.h> does not define])
	fi
])

dnl Check for UNIX95 style cmsghdr types.
dnl Solaris doesn't turn them on by default, so if the quick code
dnl snippet fails, use define _XPG4_2.  That's the define that surrounds
dnl the changes in the msghdr structure.
AC_DEFUN([LO_CHECK_CMSGHDR], [
	AC_MSG_CHECKING(if we need _XPG4_2)
	AC_TRY_COMPILE([
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/socket.h>

void foo(void) {
	struct cmsghdr c;
	struct msghdr m;
	m.msg_control = &c;
}
		],[
		],ac_check_cmsghdr=no,
		  ac_check_cmsghdr=yes
		  AC_DEFINE(_XPG4_2, 1,
			[Define for to get UNIX95 cmsghdr structures.])
	)
	AC_MSG_RESULT($ac_check_cmsghdr)
])

dnl Check for UNIX95 style cmsghdr "CMSG_LEN" macro
dnl define it if it doesn't exist. (Solaris)
AC_DEFUN([LO_CHECK_CMSG_LEN], [
	AC_MSG_CHECKING(if CMSG_LEN is defined)
	AC_TRY_COMPILE([
#define _XPG4_2 1
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <sys/socket.h>

const int size = CMSG_LEN(sizeof(int));
		],[
		],ac_check_cmsg_len=yes,
		  ac_check_cmsg_len=no
		  AC_DEFINE(LO_CMSG_DEF, 1,
			[Define if sys/socket.h doesn't.])
	)
	AC_MSG_RESULT($ac_check_cmsg_len)
])



dnl Check for the existance of pam_fail_delay and the PAM_FAIL_DELAY
dnl type for pam_get_item/pam_set_item.  If the platform doesn't support
dnl PAM_FAIL_DELAY, then we define the type macro to -1, and don't define
dnl the wrapper functions for pam_fail_delay().
AC_DEFUN([LO_CHECK_PAM_FAIL_DELAY], [
	AC_MSG_CHECKING(if there is support for pam_fail_delay)
	ac_func_search_save_LIBS=$LIBS
	LIBS="-lpam"
	AC_TRY_LINK_FUNC(pam_fail_delay,[
		lo_cv_search_pam_fail_delay=yes
		AC_DEFINE(LO_HAVE_PAM_FAIL_DELAY, 1,
			[Define if pam_fail_delay exists.])],
		[lo_cv_search_pam_fail_delay=no
		AC_DEFINE(PAM_FAIL_DELAY,-1,	
			[Define if the system headers don't.])]
	)
	LIBS=$ac_func_search_save_LIBS
	AC_MSG_RESULT($lo_cv_search_pam_fail_delay)
])

dnl Is "AF_LOCAL" defined?  If not, define it to AF_UNIX
AC_DEFUN([LO_DEF_AF_LOCAL], [
	AC_MSG_CHECKING(for AF_LOCAL)
	AC_TRY_COMPILE([
#include <sys/types.h>
#include <sys/socket.h>
		],[
int domaon = AF_LOCAL;
		],lo_def_af_local=yes,
		  lo_def_af_local=no
		  AC_DEFINE(AF_LOCAL,AF_UNIX,
			[Define if the system headers don't.])
	)
	AC_MSG_RESULT($lo_def_af_local)
])

dnl Is "LOG_AUTHPRIV" defined?  If not, define it to LOG_AUTH
AC_DEFUN([LO_DEF_LOG_AUTHPRIV], [
	AC_MSG_CHECKING(for LOG_AUTHPRIV)
	AC_TRY_COMPILE([
#include <syslog.h>
		],[
int facility = LOG_AUTHPRIV;
		],lo_def_log_authpriv=yes,
		  lo_def_log_authpriv=no
		  AC_DEFINE(LOG_AUTHPRIV,LOG_AUTH,
			[Define if the system headers don't.])
	)
	AC_MSG_RESULT($lo_def_log_authpriv)
])

dnl Solaris and Linux/BSD differ on the "const"ness of various methods.
dnl Here we test for the second arg of the conversion function being const
dnl and define a macro to either "const" or "" as needed.
AC_DEFUN([LO_PAM_CONST_CONV_FUNC], [
	AC_MSG_CHECKING(if the PAM conversion function takes const messages)
	AC_LANG_SAVE
	AC_LANG_CPLUSPLUS
	AC_TRY_COMPILE([
#if   defined(HAVE_SECURITY_PAM_APPL_H)
#include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif
		],[
int c(int, const struct pam_message **m, struct pam_response **r, void *p);

struct pam_conv pc = { c };

		],lo_pam_const_conv_func=yes , lo_pam_const_conv_func=no
	)
	if test $lo_pam_const_conv_func = "yes" ; then
		foo=const
	else
		foo=
	fi
	AC_LANG_RESTORE
	AC_DEFINE_UNQUOTED(PAM_CONV_FUNC_CONST,$foo,
			[are pam_messages const in the conv func?])
	AC_MSG_RESULT($lo_pam_const_conv_func)
])

dnl Solaris and Linux/BSD differ on the "const"ness of various methods.
dnl Here we test for the third arg of pam_get_item being const
dnl and define a macro to either "const" or "" as needed.
AC_DEFUN([LO_PAM_CONST_GET_ITEM], [
	AC_MSG_CHECKING(if the PAM get_item function takes const items)
	AC_LANG_SAVE
	AC_LANG_CPLUSPLUS
	AC_TRY_COMPILE([
#if   defined(HAVE_SECURITY_PAM_APPL_H)
#include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif
		],[
	const void **item;
	pam_get_item(0,0,item);
		],lo_pam_const_get_item=yes , lo_pam_const_get_item=no
	)
	if test $lo_pam_const_get_item = "yes" ; then
		foo=const
	else
		foo=
	fi
	AC_LANG_RESTORE
	AC_DEFINE_UNQUOTED(PAM_GET_ITEM_CONST,$foo,
			[are items const in the get_item func?])
	AC_MSG_RESULT($lo_pam_const_get_item)
])


