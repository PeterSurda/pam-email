# pam-email
This is a pam module for email authentication. It emails a token to the user
and expects the same token on a prompt

# Description

If you use it, it will send an email with a randomly generated token and
expects you to type it upon the prompt. The token is specific to a prompt and
is not stored anywhere.

It connects to localhost via port 25 and uses the curl library for SMTP.  There
is no smtp authentication. The recipient is automatically taken from the user
you are trying to authenticate as, for example, if you're trying to login as
"someguy", the RCPT TO: in the email envelope will be "someguy". The sender
(MAIL FROM) is root.

In other words, you need to have a semi-working smtp server on the machine
which uses pam_email.

The default token length is 12 characters (can be altered in the source).

The token contains only Base58 characters to avoid reading problems.

# What it looks like

The email looks like this:

>Subject: wWS9eK4s5kDg - authentication request
>
>Authentication request  for root from nobody.nowhere.edu : wWS9eK4s5kDg

If you're wondering why the token is the first word in the subject, that is in
so that it shows up when you're viewing an abbreviated version of the email,
e.g. from a notification bar on your mobile phone or without opening the email
in a mail client. It saves time.

Apart from the token, the email contains the username you're trying to
authenticate with and the IP address you're connecting from.

# How to use it

In order to compile it, you need pam and curl devel libraries. After you do a

> make install

it will copy the .so file into /lib/security.

In order to integrate it, modify your authentication PAM setup (it only
provides a function for the "auth" part of PAM). You probably shouldn't set it
up for all services, but ssh is straightforward.

For example, in order to use it with ssh, edit /etc/pam.d/sshd and search for
the auth section, in Ubuntu that's

>@include common-auth

If you want to add pam_email, i.e. use a two-factor authentication, append
pam_email like this:

>@include common-auth
>auth required pam_email.so

If you want to replace the standard password prompt only (single-factor
authentication), prepend pam_email like this:

>auth sufficient pam_email.so
>@include common-auth

# Additional steps for SSH

If you want to use it with ssh, you also need to edit /etc/ssh/sshd_config and
make sure ChallengeResponseAuthentication is on:

>ChallengeResponseAuthentication yes
