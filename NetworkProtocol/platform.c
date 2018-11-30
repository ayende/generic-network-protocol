#include "platform.h"

#if !_WIN32

int GetLastError() {
 return errno;
}

#else

int strcasecmp(const char *s1, const char *s2) {
	return _stricmp(s1, s2);
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
	return 1;
#endif
}
