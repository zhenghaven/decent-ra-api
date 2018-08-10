#include "DecentError.h"

#include <tlibc/stdarg.h>
#include <tlibc/stdio.h>      /* vsnprintf */

void ocall_printf(const char * fmt, ...)
{
	char buf[BUFSIZ] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}