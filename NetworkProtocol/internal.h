#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>
#include <openssl/asn1.h>
#include "network.h"
#include <string.h>

#define MSG_SIZE 8192


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

struct connection {
	SSL * ssl;
	int client_fd;
	struct server_state* server;
	char* buffer;
	int used_buffer;
};

struct cmd* read_message(struct connection * c);

int connection_read(struct connection *c, void* buf, int len);

int connection_write(struct connection* c, void* buf, size_t len);

int connection_write_format(struct connection* c, const char* format, ...);