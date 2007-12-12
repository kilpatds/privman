## Process this file with automake to produce Makefile.in
# Copyright © 2002  Networks Associates Technology, Inc.
# All rights reserved.
# $Id: Makefile.am,v 1.7 2003/03/08 05:41:46 dougk Exp $
EXTRA_DIST = privman.conf check_user mycat myecho myexec myrerun mypopen microb

install-data-local:
	$(mkinstalldirs) $(sysconfdir)/$(PACKAGE).d
	$(INSTALL_DATA) $(EXTRA_DIST) $(sysconfdir)/$(PACKAGE).d

MAINTAINERCLEANFILES = Makefile.in
