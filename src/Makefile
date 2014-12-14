all: pammodule

help:
	@echo "To compile run 'make' "
	@echo "To delete object file (*.o) and the executable run 'make clean' "

install: pammodule
	mkdir -p /lib/security
	cp -f pam_email.so /lib/security

pammodule:
	gcc -Wall -fPIC -c pam_email.c
	ld -x --shared -o pam_email.so pam_email.o -lpam -lcurl
	rm -f pam_email.o

clean:
	rm -f pam_email.so pam_email.o 
