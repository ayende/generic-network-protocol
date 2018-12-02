#pragma once
#define _WITH_DPRINTF

#include <stdio.h>
#include <stdarg.h>
#include "platform.h"

struct connection;
struct server_state;

// commands

struct header {
	char* key;
	char* value;
};

struct cmd {
	struct connection* connection;
	char** argv;
	int argc;
	struct header* headers;
	int headers_count;
	char* sequence;
};

void cmd_drop(struct cmd * cmd);


// error handling

struct err {
	struct err* next;
	char* msg;
	size_t len;
	int code;

	const char* file, *func;
	int line;
};

void push_error_internal(const char* file, int line, const char *func, int code, const char* format, ...);

#define push_error(code, format, ...) push_error_internal(__FILE__, __LINE__, __func__, code, format, ##__VA_ARGS__)

typedef void(*error_callback)(struct err* e, void * u);

void consume_errors(error_callback cb, void * u);

void print_all_errors(void);

void push_ssl_errors();

// ssl


struct server_state_init {
	const char* cert;
	const char* key;
	int ip;
	int port;
};

struct server_state* server_state_create(struct server_state_init* options);

void server_state_drop(struct server_state* s);

#define THUMBPRINT_HEX_LENGTH 41 // 40 chars + null terminator

int server_state_register_certificate_thumbprint(struct server_state*s, const char* thumbprint);

struct connection_setup {

	void (*connection_error)(void);

	void* (*connection_created)(struct connection* connection);

	void (*connection_dropped)(struct connection* connection, 
		void* state);

	int (*connection_recv)(struct cmd* cmd,  void* state);
};


void server_state_register_connection_setup(struct server_state* s, struct connection_setup cb);

int server_state_run(struct server_state* s);

// network


struct connection* connection_create(struct server_state* srv, int socket);

void connection_drop(struct connection* c);

int connection_reply(struct cmd* c, void* buf, size_t len);

int connection_reply_format(struct cmd* c, const char* format, ...);


// util

int vasprintf(char **strp, const char *format, va_list ap);

int asprintf(char **strp, const char *format, ...);