#include "Common.h"

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include <Enclave_t.h>

static constexpr size_t PRINT_BUFFER_SIZE = 20 * BUFSIZ;

void ocall_printf(const char * fmt, ...)
{
	char buf[PRINT_BUFFER_SIZE] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, PRINT_BUFFER_SIZE, fmt, ap);
	va_end(ap);
	ocall_print_string(buf);
}

void ocall_printf_w(const char * fmt, ...)
{
	char buf[PRINT_BUFFER_SIZE] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, PRINT_BUFFER_SIZE, fmt, ap);
	va_end(ap);
	ocall_print_string_w(buf);
}

void ocall_printf_e(const char * fmt, ...)
{
	char buf[PRINT_BUFFER_SIZE] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, PRINT_BUFFER_SIZE, fmt, ap);
	va_end(ap);
	ocall_print_string_e(buf);
}

void ocall_log_w(const char * file, int line, const char * fmt, ...)
{
	char buf[PRINT_BUFFER_SIZE] = { '\0' };
	snprintf(buf, PRINT_BUFFER_SIZE, "File:%s\nline:%d\n W: %s\n", file, line, fmt);

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, PRINT_BUFFER_SIZE, buf, ap);
	va_end(ap);
	ocall_print_string_w(buf);
}
