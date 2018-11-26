#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#include "network.h"


#ifdef _MSC_VER
_declspec(thread)
#else
thread_local
#endif
struct err* current_thread_err;


void push_error_internal(const char* file, int line, const char *func, int code, const char* format, ...) {
	struct err* error;
	va_list ap;

	error = malloc(sizeof(struct err));
	if (error == NULL)
	{
		// we are in a bad state, not much 
		// we can do at this point, so let's bail
		return;
	}

	error->code = code;
	error->file = file;
	error->line = line;
	error->func = func;
	error->next = current_thread_err;

	va_start(ap, format);

	error->len = vasprintf(&error->msg, format, ap);

	if (error->len == -1)
		error->msg = NULL;

	va_end(ap);

	current_thread_err = error;
}


void consume_errors(error_callback cb, void * u) {
	while (current_thread_err != NULL) {
		struct err* cur = current_thread_err;
		current_thread_err = current_thread_err->next;
		if (cb != NULL)
			cb(cur, u);
		if (cur->len != -1 && cur->msg != NULL)
			free(cur->msg);
		free(cur);
	}
}

void print_error(struct err* e, void *u) {
	const char* file = strrchr(e->file, '/');
	if (file == NULL)
		file = strrchr(e->file, '\\');
	if (file == NULL)
		file = e->file;
	else
		file++;// move past the directory separator

	printf("%s:%i - %s() - %i %s\n", file, e->line,
		e->func, e->code, e->msg);
}

void print_all_errors() {
	consume_errors(print_error, NULL);
}
