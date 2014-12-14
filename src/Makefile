topdir=$(shell pwd)/..
include ../Make.Rules

all: pammodule

help:
	@echo "To compile run 'make' "
	@echo "To delete object file (*.o) and the executable run 'make clean' "

install: pammodule
	mkdir -p -m 0755 $(LIBDIR)/security
	install -m 0755 pam_email.so $(LIBDIR)/security

pammodule:
	gcc -Wall -fPIC -c pam_email.c
	ld -x --shared -o pam_email.so pam_email.o -lpam -lcurl
	rm -f pam_email.o

clean:
	rm -f pam_email.so pam_email.o 
