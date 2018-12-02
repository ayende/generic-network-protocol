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

// taken from:
// https://github.com/lattera/freebsd/blob/master/lib/libc/string/strnstr.c
char *
strnstr(const char *s, const char *find, size_t slen)
{
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if (slen-- < 1 || (sc = *s++) == '\0')
					return (NULL);
			} while (sc != c);
			if (len > slen)
				return (NULL);
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char *)s);
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
