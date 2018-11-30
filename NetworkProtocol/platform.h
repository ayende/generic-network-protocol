#pragma once

#if _WIN32
#include <windows.h>
#endif


#if !_WIN32
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>

#define INVALID_SOCKET -1

int GetLastError();

#define get_server_method TLS_server_method

#else

#define get_server_method TLSv1_2_server_method

int strncasecmp(const char *s1, const char *s2, size_t size);
int close(int socket);

#endif

int network_one_time_init();


#ifdef _MSC_VER
#define thread_local_variable _declspec(thread)
#else
#define thread_local_variable __thread
#endif