#include "network.h"
#include <stdlib.h> 

#if !WIN32
int _vscprintf(const char * format, va_list pargs) {
	int retval;
	va_list argcopy;
	va_copy(argcopy, pargs);
	retval = vsnprintf(NULL, 0, format, argcopy);
	va_end(argcopy);
	return retval;
}
#endif

int asprintf(char **strp, const char *format, ...) {
	va_list ap;
	int rc;
	va_start(ap, format);

	rc = vasprintf(strp, format, ap);

	va_end(ap);

	return rc;
}

int vasprintf(char **strp, const char *format, va_list ap)
{
	int len = _vscprintf(format, ap);
	if (len == -1)
		return -1;
	char *str = (char*)malloc((size_t)len + 1);
	if (!str)
		return -1;
	int retval = vsnprintf(str, len + 1, format, ap);
	if (retval == -1) {
		free(str);
		return -1;
	}
	*strp = str;
	return retval;
}
