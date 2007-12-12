# Copyright © 2002  Networks Associates Technology, Inc.
# All rights reserved.
#
# Makefile.am
# Automake source file.  The makefile is generated from this.
#
# $Id: Makefile.am,v 1.5 2003/03/08 05:41:46 dougk Exp $
#
MAINTAINERCLEANFILES = Makefile.in

PAM_MANPAGES = priv_pam_acct_mgmt.3 priv_pam_authenticate.3		\
	       priv_pam_chauthtok.3 priv_pam_close_session.3		\
	       priv_pam_end.3 priv_pam_fail_delay.3 priv_pam_getenv.3	\
	       priv_pam_get_item.3 priv_pam_open_session.3		\
	       priv_pam_putenv.3 priv_pam_setcred.3 priv_pam_set_item.3 \
	       priv_pam_start.3

OTHER_MANPAGES = priv_open.3 priv_bind.3 priv_pam.3 priv_daemon.3	\
		 priv_execve.3 priv_fopen.3 priv_fork.3 priv_init.3	\
		 priv_rerunas.3 privman.7 privman_conf.5 priv_popen.3	\
		 priv_respawn_as.3 priv_custom.3 priv_wait4.3

POPEN_MANPAGES = priv_pclose.3

PRIV_CUSTOM_MANPAGES = priv_register_info_fn.3 priv_register_cap_fn.3	\
		priv_invoke_info_fn.3 priv_invoke_cap_fn.3

man_MANS = $(OTHER_MANPAGES) $(PAM_MANPAGES) $(POPEN_MANPAGES) 		\
		$(PRIV_CUSTOM_MANPAGES)

EXTRA_DIST = $(OTHER_MANPAGES)

$(PAM_MANPAGES):
	$(LN_S) priv_pam.3 $@

priv_pclose.3:
	$(LN_S) priv_popen.3 $@

$(PRIV_CUSTOM_MANPAGES):
	$(LN_S) priv_custom.3 $@

