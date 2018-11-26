#include <openssl/ssl.h>
#include <openssl/err.h>

#include "network.h"

struct server_state {
	SSL_CTX* ctx;
};

int configure_context(SSL_CTX *ctx, const char* cert, const char* key)
{
	int rc = SSL_CTX_set_ecdh_auto(ctx, 1);
	if (rc == 0) {
		push_ssl_errors();
		push_error(EINVAL, "Unable setup ECDH negotiation");
		return 0;
	}

	if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
		push_ssl_errors();
		push_error(EINVAL, "Unable register certificiate file: %s", cert);
		return 0;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
		push_ssl_errors();
		push_error(EINVAL, "Unable register key file: %s", key);
		return 0;
	}

	return 1;
}

struct server_state* server_state_create(const char* cert, const char* key) {
	struct server_state* state;
	const SSL_METHOD *method;
	static int first_time_init_done;

	if (!first_time_init_done) {
		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();
		first_time_init_done = 1;
	}

	state = malloc(sizeof(struct server_state));
	if (state == NULL) {
		push_error(ENOMEM, "Unable to allocate server state");
		return NULL;
	}
	memset(state, 0, sizeof(struct server_state));

	method = TLSv1_2_server_method();
	if (method == NULL) {
		free(state);
		push_ssl_errors();
		push_error(EINVAL, "Unable to create TLS 1.2 server method");
		return NULL;
	}

	state->ctx = SSL_CTX_new(method);
	if (state->ctx == NULL) {
		free(state);
		push_ssl_errors();
		push_error(EINVAL, "Unable to SSL ctx");
		return NULL;
	}

	if (!configure_context(state->ctx, cert, key)) {
		free(state);
		push_ssl_errors();
		push_error(EINVAL, "Unable to configure SSL ctx with provided cert(%s) / key (%s)", cert, key);
		return NULL;
	}
	
	return state;
}


void server_state_drop(struct server_state* s) {
	SSL_CTX_free(s->ctx);
	free(s);
}

struct connection {
	SSL * ssl;
	int client_fd;
};



struct connection* connection_create(struct server_state* srv, int socket) {
	int rc;
	struct connection* c = malloc(sizeof(struct connection));
	if (c == NULL)
	{
		push_error(ENOMEM, "Unable to allocate memory for connection");
		goto error_cleanup;
	}

	memset(c, 0, sizeof(struct connection));
	c->ssl = SSL_new(srv->ctx);
	if (c->ssl == NULL)
	{
		push_error(ENOMEM, "Failed to create new SSL struct");
		goto error_cleanup;
	}
	c->client_fd = socket;
	if (!SSL_set_fd(c->ssl, socket))
	{
		push_error(EBADF, "Failed to associate the new SSL context with the provided socket");
		goto error_cleanup;
	}

	rc = SSL_accept(c->ssl);
	if (rc == 0) {
		push_error(ENETRESET, "Could not establish TLS connectionto client: %i", SSL_get_error(c->ssl, rc));
		goto error_cleanup;
	}

	return c;

error_cleanup:
	if (c != NULL) {
		if (c->ssl != NULL) {
			SSL_free(c->ssl);
			c->ssl = NULL;
		}
		free(c);
	}
	return NULL;
}


void connection_drop(struct connection* c) {
	SSL_free(c->ssl);
	closesocket(c->client_fd);
	free(c);
}

int connection_write(struct connection* c, void* buf, size_t len) {
	int rc = SSL_write(c->ssl, buf, len);
	if (rc <= 0) {
		push_error(ENETRESET, "Unable to write message to connection: %i", SSL_get_error(c->ssl, rc));
		return 0;
	}

	return 1;
}

int connection_write_format(struct connection* c, const char* format, ...) {
	va_list ap;
	int rc;
	va_start(ap, format);
	char * msg;
	int len = vasprintf(&msg, format, ap);
	va_end(ap);

	if (len == -1) {
		push_error(EINVAL, "Failed to format message to write to connection");
		return 0;
	}

	rc = connection_write(c, msg, len);
	free(msg);
	return rc;
}

int connection_read(struct connection *c, void* buf, int len) {

	int rc = SSL_read(c->ssl, buf, len);
	if (rc <= 0) {
		push_error(ENETRESET, "Unable to read message from connection: %i", SSL_get_error(c->ssl, rc));
		return 0;
	}
	return rc;
}


int push_single_ssl_error(const char * str, size_t len, void * _) {
	push_error(EINVAL, "%.*s", len, str);//write a size terminated string
	return 1;
}

void push_ssl_errors() {
	ERR_print_errors_cb(push_single_ssl_error, NULL);
}
