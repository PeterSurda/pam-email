#
# Makefile for pam-email
#
topdir=$(shell pwd)
include Make.Rules

#
# flags
#

all install clean: %: %-here
	$(MAKE) -C src $@

all-here:

install-here:

clean-here:
	$(LOCALCLEAN)

distclean: clean
	$(DISTCLEAN)

release: distclean
	cd .. && tar --exclude cvf pam-email/.git pam-email-$(VERSION).$(MINOR).tar pam-email/*

tagrelease: distclean
	make release
