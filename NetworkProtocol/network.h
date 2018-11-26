#pragma once
#define _WITH_DPRINTF

#include <stdio.h>
#include <stdarg.h>

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

#define push_error(code, format, ...) push_error_internal(__FILE__, __LINE__, __func__, code, format, __VA_ARGS__)

typedef void(*error_callback)(struct err* e, void * u);

void consume_errors(error_callback cb, void * u);

void print_all_errors();

void push_ssl_errors();

// ssl

struct server_state;

struct server_state* server_state_create(const char* cert, const char* key);

void server_state_drop(struct server_state* s);

// network

struct connection;

struct connection* connection_create(struct server_state* srv, int socket);

void connection_drop(struct connection* c);

int connection_write(struct connection* c, void* buf, size_t len);

int connection_read(struct connection *c, void* buf, int len);

int connection_write_format(struct connection* c, const char* format, ...);

// util

int vasprintf(char **strp, const char *format, va_list ap);