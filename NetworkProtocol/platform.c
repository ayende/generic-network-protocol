#include "platform.h"

#if !_WIN32

int GetLastError() {
 return errno;
}

#else

int strncasecmp(const char *s1, const char *s2, size_t size) {
	return _strnicmp(s1, s2, size	);
}

int close(int socket) {
	return closesocket(socket);
}

#endif


int network_one_time_init() {
#if _WIN32
	WSADATA wsaData;
	return WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
	return 0;
#endif
}
