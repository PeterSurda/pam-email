/*
 * pam_email.c
 *
 * Author: Peter Surda <surda@economicsofbitcoin.com> ()
 * Parts taken from pam_retisms.c by Andrea Biancini <andrea.biancini@reti.it>
 * Parts taken from pam_http.c by Jameson Little <beatgammit@gmail.com>
 * Parts taken from smtp_tls.c by Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#include <curl/curl.h>
#include <curl/easy.h>

#define TOKSYMBOLS "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"
#define TOK_MSG "Token: "
#define EMAIL_FROM "root"
#define EMAIL_SUBJ_PRE ""
#define EMAIL_SUBJ_POST " - authentication request"
#define EMAIL_BODY "Authentication request "
#define TOKLEN 12

struct upload_status {
  int lines_read;
  const char* user_name;
  const char* ip;
  const char* token;
};

/*
 * Makes getting arguments easier. Accepted arguments are of the form: name=value
 * 
 * @param argn- name of the argument to get
 * @param argc- number of total arguments
 * @param argv- arguments
 * @return Pointer to value or NULL
 */
static const char* get_arg(const char* argn, int argc, const char** argv) {
	int len = strlen(argn);
	int i;

	for (i = 0; i < argc; i++) {
		if (strncmp(argn, argv[i], len) == 0 && argv[i][len] == '=') {
			// only give the part url part (after the equals sign)
			return argv[i] + len + 1;
		}
	}
	return 0;
}

char *generate_token(int length) {
	char *values = TOKSYMBOLS;
	int mod = strlen(values);
	char *retval = calloc(length + 1, sizeof(char));
	int i;

	srand(time(NULL));
	for(i = 0; i < length; i++)
		retval[i] = values[rand() % mod];

	return retval;
}

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
	struct upload_status *upload_ctx = (struct upload_status *)userp;
	size_t len = 0;
 
	if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1))
		return 0;
	if (size * nmemb < 1024) // fixme
		return 0;
 
	switch (upload_ctx->lines_read) {
		case 0:
			len = sprintf (ptr, "Subject: %s%s%s\r\n", EMAIL_SUBJ_PRE, upload_ctx->token, EMAIL_SUBJ_POST);
			if (len > 0) upload_ctx->lines_read++;
			break;
		case 1:
			len = sprintf (ptr, "\r\n");
			if (len > 0) upload_ctx->lines_read++;
			break;
		case 2:
			len = sprintf (ptr, "%s for %s from %s : %s\r\n", EMAIL_BODY, upload_ctx->user_name, upload_ctx->ip, upload_ctx->token);
			if (len > 0) upload_ctx->lines_read++;
			break;
		default:
			upload_ctx->lines_read++;
			break;
	}
 
	return len;
}

static int send_token(const char* user_name, char* token, const char* ip) {

	if (user_name == NULL) return 0;

	CURL* curl = curl_easy_init();
	if (!curl) return 0;

	CURLcode res = CURLE_OK;

	struct curl_slist *recipients = NULL;
	struct upload_status upload_ctx;

	upload_ctx.lines_read = 0;
	upload_ctx.user_name = user_name;
	upload_ctx.ip = ip;
	upload_ctx.token = token;

	recipients = curl_slist_append(recipients, user_name);

	curl_easy_setopt(curl, CURLOPT_URL, "smtp://localhost:25");
	curl_easy_setopt(curl, CURLOPT_MAIL_FROM, EMAIL_FROM);
	curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
	
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1); // we don't care about progress
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);

	/* We're using a callback function to specify the payload (the headers and
	* body of the message). You could just use the CURLOPT_READDATA option to
	* specify a FILE pointer to read from. */ 
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

	// synchronous, but we don't really care
	res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	curl_slist_free_all(recipients);
	return res;
}

int pam_converse(pam_handle_t *pamh, const char *message, char **response, int type) {
	int pam_err = 0;

	char *mresponse = NULL;

	struct pam_conv *conv;
	struct pam_message msg;
	const struct pam_message *msgp;
	struct pam_response *resp;

	pam_err = pam_get_item(pamh, PAM_CONV, (const void **) &conv);

	if (pam_err != PAM_SUCCESS)
		return -1;

	msg.msg_style = type;
	msg.msg = message;
	msgp = &msg;

	resp = NULL;
	pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);

	if (resp != NULL) {
		if (pam_err == PAM_SUCCESS) {
			mresponse = resp->resp;
			pam_err = 0;
		}
		else {
			free(resp->resp);
			pam_err = -1;
		}
		free(resp);
	}

	response[0] = mresponse;
	return pam_err;
}

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	int retval;
	const char *user = NULL;
	const char *ip = NULL;
	char *token = NULL;
	char *recv_token = NULL;
	int num_char_tok = TOKLEN;

	// authentication requires we know who the user wants to be
	retval = pam_get_user(pamh, &user, NULL);
	if (retval != PAM_SUCCESS) {
		syslog(LOG_ALERT, "get user returned error: %s", pam_strerror(pamh, retval));
		return retval;
	}

	if (user == NULL || *user == '\0') {
		return PAM_USER_UNKNOWN;
	}

	retval = pam_get_item(pamh, PAM_RHOST, (const void **) &ip);
	if (retval != PAM_SUCCESS) {
		syslog(LOG_ALERT, "Error getting PAM_RHOST");
	}

	token = generate_token(num_char_tok);
	send_token (user, token, ip);

	if (pam_converse(pamh, TOK_MSG, &recv_token, PAM_PROMPT_ECHO_ON) != 0) {
		free(token);
		return PAM_CONV_ERR;
	}

	// compare the sent token and the received one and respond correspondingly
	if (strncmp(token, recv_token, num_char_tok) == 0) {
		retval = PAM_SUCCESS;
	}
	else {
		retval = PAM_AUTH_ERR;
	}

	recv_token = NULL;
	free(token);
	user = NULL;
	return retval;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

/* --- account management functions --- */

PAM_EXTERN
int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

/* --- password management --- */

PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

/* --- session management --- */

PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
     return PAM_SUCCESS;
}

/* end of module definition */

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_permit_modstruct = {
	"pam_email",
	pam_sm_authenticate,
	pam_sm_setcred,
	pam_sm_acct_mgmt,
	pam_sm_open_session,
	pam_sm_close_session,
	pam_sm_chauthtok
};

#endif
