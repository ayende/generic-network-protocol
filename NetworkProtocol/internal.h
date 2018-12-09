#pragma once
#include <time.h>
#include "network.h"
#include "internal.h"

typedef struct server_state {
	SSL_CTX* ctx;
	uv_loop_t* loop;
	server_state_init_t options;
	tls_uv_connection_state_t* pending_writes;
} server_state_t;



int read_message(tls_uv_connection_state_t* c, void* buffer, int nread);

int connection_write(tls_uv_connection_state_t* c, void* buf, size_t len);

int connection_write_format(tls_uv_connection_state_t* c, const char* format, ...);

char * strnstr(const char *s, const char *find, size_t slen);
