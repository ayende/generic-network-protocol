#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <openssl/asn1.h>
#include "network.h"
#include <string.h>

struct certificate_thumbprint {
	char thumbprint[THUMBPRINT_HEX_LENGTH];
};

struct server_state {
	SSL_CTX* ctx;
	size_t certs_len, certs_capacity;
	struct certificate_thumbprint* certs;
	struct connection_setup cb;
	struct server_state_init options;
};

void server_state_register_connection_setup(struct server_state* s, struct connection_setup cb) {
	s->cb = cb;
}

int server_state_register_certificate_thumbprint(struct server_state*s, const char* thumbprint) {
	if (s->certs_len + 1 >= s->certs_capacity) {

		struct certificate_thumbprint* buffer;
		int new_size = s->certs_capacity < 1 ? 1 : s->certs_capacity * 2;

		buffer = realloc(s->certs, new_size * sizeof(struct certificate_thumbprint));
		if (buffer == NULL) {
			push_error(ENOMEM, "Could not allocate memory for thumbprint");
			return 0;
		}

		s->certs = buffer;
		s->certs_capacity = new_size;
	}

	if (strlen(thumbprint) != THUMBPRINT_HEX_LENGTH -1 /*null terminator */) {
		push_error(EINVAL, "Unexpected thmbuprint size");
		return 0;
	}
	
	memcpy(&s->certs[s->certs_len++], thumbprint, THUMBPRINT_HEX_LENGTH);
	return 1;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	// we want to give good errors, so we acccept all certs
	// and validate them manually
	return 1;
}

int configure_context(SSL_CTX *ctx, const char* cert, const char* key)
{
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

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

	return 1;
}


int create_server_socket(int ip, int port)
{
	int s;
	int rc;
	struct sockaddr_in addr;

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(ip);

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		push_error(ENETUNREACH, "Unable to create socket for listening on port: %i", port);
		return -1;
	}

	rc = bind(s, (struct sockaddr*)&addr, sizeof(addr));
	if (rc != 0) {
		close(s);
		push_error(rc, "Unable to bind socket on port: %i, error: %i", port, rc);
		return -1;
	}

	rc = listen(s, 2);

	if (rc != 0) {
		close(s);
		push_error(rc, "Unable to listen to socket on port: %i, error: %i", port, rc);
		return -1;
	}

	return s;
}

struct server_state* server_state_create(struct server_state_init* options) {
	struct server_state* state;
	const SSL_METHOD *method;
	static int first_time_init_done;

	if (!first_time_init_done) {
		int rc = network_one_time_init();
		if (rc != 0) {
			push_error(rc, "Unable to initialize network properly %i", rc);
			return NULL;
		}

		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();
		first_time_init_done = 1;
	}

	state = calloc(1, sizeof(struct server_state));
	if (state == NULL) {
		push_error(ENOMEM, "Unable to allocate server state");
		return NULL;
	}

	state->options = *options;

	method = get_server_method();

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

	if (!configure_context(state->ctx, options->cert, options->key)) {
		free(state);
		push_ssl_errors();
		push_error(EINVAL, "Unable to configure SSL ctx with provided cert(%s) / key (%s)", options->cert, options->key);
		return NULL;
	}
	
	return state;
}


void server_state_drop(struct server_state* s) {
	if(s->certs != NULL)
		free(s->certs);

	SSL_CTX_free(s->ctx);

	free(s);	
}

struct connection {
	SSL * ssl;
	int client_fd;
	struct server_state* server;
};

int validate_connection_certificate(struct connection * c)
{
	int free_err = 0;
	ASN1_TIME* time;
	int day, sec, len, rc = 0;
	unsigned char digest[SHA_DIGEST_LENGTH];
	char digest_hex[THUMBPRINT_HEX_LENGTH];
	char*err = NULL;

	X509* client_cert = SSL_get_peer_certificate(c->ssl);
	if (client_cert == NULL) {
		err = "No certificate was sent, but this is required, aborting.";
		goto error;
	}
	time = X509_get_notAfter(client_cert);
	if (!ASN1_TIME_diff(&day, &sec, NULL, time)) {
		push_ssl_errors();
		err = "Invalid certificate time - NotAfter";
		goto error;
	}
	if (day < 0 || sec < 0) {
		err = "Certificate expired";
		goto error;
	}
	time = X509_get_notBefore(client_cert);
	if (!ASN1_TIME_diff(&day, &sec, NULL, time)) {
		push_ssl_errors();
		err = "Invalid certificate time - NotBefore";
		goto error;
	}
	if (day > 0 || sec > 0) {
		err = "Certificate isn't valid yet";
		goto error;
	}

	if (!X509_digest(client_cert, EVP_sha1(), digest, &len)) {
		err = "Failed to compute certificate digest";
		goto error;
	}

	for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
		int rc = snprintf(digest_hex + (i * 2), 3/* for the null terminator*/, "%02X", digest[i]);
		if (rc != 2) {
			err = "Failed to format certificate digest";
			goto error;
		}
	}
	for (size_t i = 0; i < c->server->certs_len; i++)
	{
		if (strncasecmp(digest_hex, c->server->certs[i].thumbprint, THUMBPRINT_HEX_LENGTH) == 0)
		{
			rc = 1;
			goto done;
		}
	}

	rc = asprintf(&err, "Unfamiliar certificate %s", digest_hex);
	if (rc == -1)
		err = "Unfamiliar cert";
	else
		free_err = 1;

error:
	connection_write_format(c, "ERR: %s\r\n", err); // notify remote
	push_error(EINVAL, err);  // notify locally;
	if (free_err)
		free(err);
	rc = 0;
done:
	if (client_cert != NULL)
		X509_free(client_cert);
	return rc;
}

struct connection* connection_create(struct server_state* srv, int socket) {
	int rc;
	struct connection* c = calloc(1, sizeof(struct connection));
	if (c == NULL)
	{
		push_error(ENOMEM, "Unable to allocate memory for connection");
		goto error_cleanup;
	}
	c->server = srv;
	c->ssl = SSL_new(srv->ctx);
	if (c->ssl == NULL)
	{
		push_ssl_errors();
		push_error(ENOMEM, "Failed to create new SSL struct");
		goto error_cleanup;
	}
	c->client_fd = socket;
	if (!SSL_set_fd(c->ssl, socket))
	{
		push_ssl_errors();
		push_error(EBADF, "Failed to associate the new SSL context with the provided socket");
		goto error_cleanup;
	}

	rc = SSL_accept(c->ssl);
	if (rc <= 0) {
		push_ssl_errors();
		push_error(ENETRESET, "Could not establish TLS connection to client: %i", SSL_get_error(c->ssl, rc));
		goto error_cleanup;
	}

	// now need to validate the certificate...
	if(!validate_connection_certificate(c))
		goto error_cleanup;

	if (!connection_write(c, "OK\r\n", 4))
		goto error_cleanup;

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
	close(c->client_fd);
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

static int connection_read(struct connection *c, void* buf, int len) {

	int rc = SSL_read(c->ssl, buf, len);
	if (rc <= 0) {
		push_error(ENETRESET, "Unable to read message from connection: %i", SSL_get_error(c->ssl, rc));
		return 0;
	}
	return rc;
}

int server_state_run(struct server_state* s) {
	int rc;
	int accept_more_connections = 1;
	char buffer[256];
	int socket = create_server_socket(s->options.ip, s->options.port);
	if (socket == -1) {
		push_error(EINVAL, "Unable to create socket");
		return 0;
	}

	while (accept_more_connections) {
		struct sockaddr_in addr;
		struct connection* con;
		unsigned int len = sizeof(addr);
		void* connection_state;

		int client = accept(socket, (struct sockaddr*)&addr, &len);
		if (client == INVALID_SOCKET) {
			push_error(ENETRESET, "Unable to accept connection, error: %i",
				GetLastError());
			// failure to accept impacts everything, we'll abort
			goto handle_error;
		}

		con = connection_create(s, client);

		if (con == NULL)
			goto handle_connection_error;

		connection_state = s->cb.connection_created == NULL ? 
			NULL :
			s->cb.connection_created(con);

		while (1)
		{
			rc = connection_read(con, buffer, sizeof buffer);
			if (rc == 0) {
				break;
			}

			if (strncasecmp("quit\r\n", buffer, 6) == 0)
			{
				accept_more_connections = 0;
				break;
			}

			rc = s->cb.connection_recv(con, connection_state, buffer, rc);

			if (rc == 0) {
				
				break;
			}
		}

	handle_connection_error:
		if (s->cb.connection_error != NULL)
			s->cb.connection_error();
		consume_errors(NULL, NULL);

		if (con != NULL) {
			connection_drop(con);
		}
		else { // can only happen if we failed to create connection, but already accepted it
			close(client);
		}

		// now go back and accept another connection
	}

handle_error:

	if (socket != -1)
		close(socket);

	return !accept_more_connections;
}


int push_single_ssl_error(const char * str, size_t len, void * _) {
	push_error(EINVAL, "%.*s", len, str);//write a size terminated string
	return 1;
}

void push_ssl_errors() {
	ERR_print_errors_cb(push_single_ssl_error, NULL);
}
