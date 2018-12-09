#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <openssl/asn1.h>
#include "network.h"
#include <string.h>
#include "internal.h"
#include <uv.h>
#include <assert.h>

void maybe_flush_ssl(tls_uv_connection_state_t* state);

static int verify_ssl_x509_certificate_callback(int preverify_ok, X509_STORE_CTX *ctx)
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

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_ssl_x509_certificate_callback);

	return 1;
}

server_state_t* server_state_create(server_state_init_t* options) {
	server_state_t* state;
	const SSL_METHOD *method;
	static int first_time_init_done;

	if (!first_time_init_done) {
		int rc = network_one_time_init();
		if (rc != 0) {
			push_error(rc, "Unable to initialize network properly %i", rc);
			return NULL;
		}

		SSL_load_error_strings();
		ERR_load_BIO_strings();
		ERR_load_crypto_strings();
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


void server_state_drop(server_state_t* s) {
	SSL_CTX_free(s->ctx);

	free(s);	
}

int validate_connection_certificate(tls_uv_connection_state_t* c)
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
	for (int i = 0; i < c->server->options.known_thumprints_count; i++)
	{
		if (strncasecmp(digest_hex, c->server->options.known_thumprints[i], THUMBPRINT_HEX_LENGTH) == 0)
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

int connection_write(tls_uv_connection_state_t* c, void* buf, size_t len) {
	int rc = SSL_write(c->ssl, buf, len);
	if (rc <= 0) {
		push_error(ENETRESET, "Unable to write message to connection: %i", SSL_get_error(c->ssl, rc));
		return 0;
	}
	maybe_flush_ssl(c);
	return 1;
}

int connection_write_format(tls_uv_connection_state_t* c, const char* format, ...) {
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

void remove_connection_from_queue(tls_uv_connection_state_t* cur) {
	if (cur->pending.pending_writes_buffer != NULL) {
		free(cur->pending.pending_writes_buffer);
	}
	if (cur->pending.prev_holder != NULL) {
		*cur->pending.prev_holder = cur->pending.next;
	}

	memset(&cur->pending, 0, sizeof(cur->pending));
}

void abort_connection_on_error(tls_uv_connection_state_t* state) {
	uv_close((uv_handle_t*)state->handle, NULL);
	SSL_free(state->ssl);
	remove_connection_from_queue(state);
	free(state);
}

void complete_write(uv_write_t* r, int status) {
	tls_uv_connection_state_t* state = r->data;
	free(r->write_buffer.base);
	free(r);

	if (status < 0) {
		push_error(status, "Failed to write to connection");
	}
	else if (state->flags & CONNECTION_STATUS_WRITE_AND_ABORT) {
		push_error(status, "Done writing buffered error message, now aborting connection");
	}
	else {
		return;
	}


	state->server->options.handler->connection_error(state);
	abort_connection_on_error(state);


}


int flush_ssl_buffer(tls_uv_connection_state_t* cur) {
	int rc = BIO_pending(cur->write);
	if (rc > 0) {
		void* mem = malloc(rc);
		if (mem == NULL) {
			push_error(ENOMEM, "Unable to allocate memory to flush SSL");
			return 0;
		}
		uv_buf_t buf = uv_buf_init(mem, rc);
		rc = BIO_read(cur->write, buf.base, rc);
		if (rc <= 0)
		{
			free(mem);
			return 1;// nothing to read, that is fine
		}
		uv_write_t* r = calloc(1, sizeof(uv_write_t));
		if (r == NULL) {
			push_error(ENOMEM, "Unable to allocate memory to flush SSL");
			free(r);
			return 0;
		}
		r->data = cur;
		rc = uv_write(r, (uv_stream_t*)cur->handle, &buf, 1, complete_write);
		if (rc < 0) {
			push_libuv_error(rc, "uv_write");
			free(r);
			free(mem);
			return 0;
		}
	}
	return 1;
}


void try_flush_ssl_state(uv_handle_t * handle) {
	server_state_t* server_state = handle->data;
	tls_uv_connection_state_t** head = &server_state->pending_writes;
	int rc;
	while (*head != NULL) {
		tls_uv_connection_state_t* cur = *head;

		rc = flush_ssl_buffer(cur);

		if (rc == 0) {
			push_error(rc, "Failed to flush SSL buffer");
			server_state->options.handler->connection_error(cur);
			abort_connection_on_error(cur);
			continue;
		}

		if (cur->pending.pending_writes_count == 0) {
			remove_connection_from_queue(cur);
			continue;
		}

		// here we have pending writes to deal with, so we'll try stuffing them
		// into the SSL buffer
		int used = 0;
		for (size_t i = 0; i < cur->pending.pending_writes_count; i++)
		{
			int rc = SSL_write(cur->ssl,
				cur->pending.pending_writes_buffer[i].base,
				cur->pending.pending_writes_buffer[i].len);
			if (rc > 0) {
				used++;
				continue;
			}
			rc = SSL_get_error(cur->ssl, rc);
			if (rc == SSL_ERROR_WANT_WRITE) {
				flush_ssl_buffer(cur);
				i--;// retry
				continue;
			}
			if (rc != SSL_ERROR_WANT_READ) {
				push_ssl_errors();
				server_state->options.handler->connection_error(cur);
				abort_connection_on_error(cur);
				cur->pending.in_queue = 0;
				break;
			}
			// we are waiting for reads from the network
			// we can't remove this instance, so we play
			// with the pointer and start the scan/remove 
			// from this position
			head = &cur->pending.next;
			break;
		}
		rc = flush_ssl_buffer(cur);
		if (rc == 0) {
			push_error(rc, "Failed to flush SSL buffer");
			server_state->options.handler->connection_error(cur);
			abort_connection_on_error(cur);
			continue;
		}
		if (used == cur->pending.pending_writes_count) {
			remove_connection_from_queue(cur);
		}
		else {
			cur->pending.pending_writes_count -= used;
			memmove(cur->pending.pending_writes_buffer,
				cur->pending.pending_writes_buffer + sizeof(uv_buf_t)*used,
				sizeof(uv_buf_t) * cur->pending.pending_writes_count);
		}
	}
}

void prepare_if_need_to_flush_ssl_state(uv_prepare_t * handle) {
	try_flush_ssl_state((uv_handle_t*)handle);
}
void check_if_need_to_flush_ssl_state(uv_check_t * handle) {
	try_flush_ssl_state((uv_handle_t*)handle);
}

void alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	buf->base = (char*)malloc(suggested_size);
	buf->len = suggested_size;
}

void maybe_flush_ssl(tls_uv_connection_state_t* state) {
	if (state->pending.in_queue)
		return;
	if (BIO_pending(state->write) == 0 && state->pending.pending_writes_count > 0)
		return;
	state->pending.next = state->server->pending_writes;
	if (state->pending.next != NULL) {
		state->pending.next->pending.prev_holder = &state->pending.next;
	}
	state->pending.prev_holder = &state->server->pending_writes;
	state->pending.in_queue = 1;

	state->server->pending_writes = state;
}

void handle_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf) {
	tls_uv_connection_state_t* state = client->data;
	if (nread <= 0) {
		push_libuv_error(nread, "Unable to read");
		state->server->options.handler->connection_error(state);
		abort_connection_on_error(state);
		return;
	}


	int rc = BIO_write(state->read, buf->base, nread);
	assert(rc == nread);
	while (1)
	{
		int rc = SSL_read(state->ssl, buf->base, buf->len);
		if (rc <= 0) {
			rc = SSL_get_error(state->ssl, rc);
			if (rc != SSL_ERROR_WANT_READ) {
				push_ssl_errors();
				state->server->options.handler->connection_error(state);
				abort_connection_on_error(state);
				break;
			}

			if ((state->flags & CONNECTION_STATUS_INIT_DONE) == 0){
				if (SSL_is_init_finished(state->ssl)) {
					state->flags |= CONNECTION_STATUS_INIT_DONE;
					if (validate_connection_certificate(state) == 0) {
						state->flags |= CONNECTION_STATUS_WRITE_AND_ABORT;
						break;
					}
					connection_write(state, "OK\r\n", 4);
				}
			}

			maybe_flush_ssl(state);
			// need to read more, we'll let libuv handle this
			break;
		}
		if (state->flags & CONNECTION_STATUS_WRITE_AND_ABORT) {
			// we won't accept anything from this kind of connection
			// just read it out of the network and let's give the write
			// a chance to kill it
			continue;
		}
		if (read_message(state, buf->base, rc) == 0) {
			// handler asked to close the socket
			abort_connection_on_error(state);
			break;
		}
	}

	free(buf->base);
}

void on_new_connection(uv_stream_t *server, int status) {
	uv_tcp_t *client = NULL;
	tls_uv_connection_state_t* state = NULL;
	server_state_t* server_state = server->data;
	if (status < 0) {
		push_libuv_error(status, "Unable to accept new connection");
		goto error_handler;
	}

	client = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	if (client == NULL) {
		push_error(ENOMEM, "Unable to allocate memory for new connection");
		goto error_handler;
	}
	int rc = uv_tcp_init(server_state->loop, client);
	if (rc < 0) {
		push_libuv_error(rc, "uv_tcp_init");
		goto error_handler;
	}
	status = uv_accept(server, (uv_stream_t*)client);
	if (status != 0) {
		push_libuv_error(rc, "uv_tcp_init");
		goto error_handler;
	}
	state = server_state->options.handler->create_connection();
	if (state == NULL) {
		push_error(ENOMEM, "create_connection callback returned NULL");
		goto error_handler;
	}
	memset(state, 0, sizeof(struct tls_uv_connection_state_private_members));
	state->ssl = SSL_new(server_state->ctx);
	if (state->ssl == NULL) {
		push_error(ENOMEM, "Unable to allocate SSL for connection");
		goto error_handler;
	}
	SSL_set_accept_state(state->ssl);
	state->server = server_state;
	state->handle = client;
	state->read = BIO_new(BIO_s_mem());
	state->write = BIO_new(BIO_s_mem());
	if (state->read == NULL || state->write == NULL) {
		push_error(ENOMEM, "Unable to allocate I/O for connection");
		goto error_handler;
	}

	BIO_set_nbio(state->read, 1);
	BIO_set_nbio(state->write, 1);
	SSL_set_bio(state->ssl, state->read, state->write);

	client->data = state;

	rc = uv_read_start((uv_stream_t*)client, alloc_buffer, handle_read);
	if (rc < 0) {
		push_libuv_error(rc, "uv_read_start");
		goto error_handler;
	}

	return;

error_handler:

	if (client != NULL) {
		uv_close((uv_handle_t*)client, NULL);
		free(client);
	}
	if (state != NULL) {
		if (state->ssl != NULL) {
			if (SSL_get_rbio(state->ssl) != NULL)
				state->read = NULL;
			if (SSL_get_wbio(state->ssl) != NULL)
				state->write = NULL;
			SSL_free(state->ssl);
		}
		if (state->read != NULL) {
			BIO_free(state->read);
		}
		if (state->write != NULL) {
			BIO_free(state->write);
		}
	}
	server_state->options.handler->failed_connection();
}

int server_state_run(server_state_t* s) {
	
	s->loop = uv_default_loop();
	if (s->loop == NULL) {
		push_error(ENOMEM, "Unable to allocate a uv loop");
		goto error_cleanup;
	}
	
	uv_tcp_t server;
	int rc = uv_tcp_init(s->loop, &server);
	if (rc != 0) {
		push_libuv_error(rc, "uv_tcp_init");
		goto error_cleanup;
	}
	server.data = s;
	struct sockaddr_in addr;
	rc = uv_ip4_addr(s->options.address, s->options.port, &addr);
	if (rc != 0) {
		push_libuv_error(rc, "uv_ip4_addr(%s, %i, addr)", s->options.address, s->options.port);
		goto error_cleanup;
	}

	rc = uv_tcp_bind(&server, (const struct sockaddr*)&addr, 0);
	if (rc != 0) {
		push_libuv_error(rc, "uv_tcp_bind(%s : %i)", s->options.address, s->options.port);
		goto error_cleanup;
	}
	rc = uv_listen((uv_stream_t*)&server, 128, on_new_connection);
	if (rc != 0) {
		push_libuv_error(rc, "uv_listen(%s : %i)", s->options.address, s->options.port);
		goto error_cleanup;
	}
	uv_prepare_t before_io;
	before_io.data = s;
	rc = uv_prepare_init(s->loop, &before_io);
	if (rc != 0) {
		push_libuv_error(rc, "uv_prepare_init");
		goto error_cleanup;
	}
	rc = uv_prepare_start(&before_io, prepare_if_need_to_flush_ssl_state);
	if (rc != 0) {
		push_libuv_error(rc, "uv_prepare_start");
		goto error_cleanup;
	}
	uv_check_t after_io;
	after_io.data = s;
	rc = uv_check_init(s->loop, &after_io);
	if (rc != 0) {
		push_libuv_error(rc, "uv_check_init");
		goto error_cleanup;
	}
	rc = uv_check_start(&after_io, check_if_need_to_flush_ssl_state);
	if (rc != 0) {
		push_libuv_error(rc, "uv_check_start");
		goto error_cleanup;
	}

	rc = uv_run(s->loop, UV_RUN_DEFAULT);
	
error_cleanup:
	
	if (s->loop != NULL) {
		uv_loop_close(s->loop);
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

void push_libuv_error(int rc, const char* operation, ...) {
	char tmp[256];
	uv_strerror_r(rc, tmp, 256);

	va_list ap;
	va_start(ap, operation);
	char* msg;
	if (vasprintf(&msg, operation, ap) != -1) {
		operation = msg;
	}
	else {
		msg = NULL;
	}
	va_end(ap);

	push_error(rc, "libuv err: %s failed with %i - %s", msg, rc, tmp);
	if(msg != NULL)
		free(msg);
}
