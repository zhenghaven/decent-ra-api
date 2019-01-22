#include "../../common/Common.h"

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "../../common/make_unique.h"

#include "edl_decent_tools.h"

using namespace Decent;

namespace
{
	static constexpr size_t PRINT_BUFFER_SIZE = 20 * BUFSIZ;
}

void Tools::Printf(const char * fmt, ...)
{
	char buf[PRINT_BUFFER_SIZE] = { '\0' };
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, PRINT_BUFFER_SIZE, fmt, ap);
	va_end(ap);
	ocall_decent_tools_print_string(buf);
}

void Tools::LogInfo(const char* fmt, ...)
{
	char buf[PRINT_BUFFER_SIZE] = { '\0' };
	int fmtLen = snprintf(buf, PRINT_BUFFER_SIZE, "I: %s\n", fmt);
	if (fmtLen <= 0)
	{
		return;
	}

	++fmtLen;
	std::unique_ptr<char[]> resFmt = Decent::Tools::make_unique<char[]>(fmtLen);
	std::memcpy(resFmt.get(), buf, fmtLen);

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, PRINT_BUFFER_SIZE, resFmt.get(), ap);
	va_end(ap);
	ocall_decent_tools_print_string_i(buf);
}

void Tools::LogWarning(const char* file, int line, const char* fmt, ...)
{
	char buf[PRINT_BUFFER_SIZE] = { '\0' };
	int fmtLen = snprintf(buf, PRINT_BUFFER_SIZE, "File:%s\nline:%d\n W: %s\n", file, line, fmt);
	if (fmtLen <= 0)
	{
		return;
	}

	++fmtLen;
	std::unique_ptr<char[]> resFmt = Decent::Tools::make_unique<char[]>(fmtLen);
	std::memcpy(resFmt.get(), buf, fmtLen);

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, PRINT_BUFFER_SIZE, resFmt.get(), ap);
	va_end(ap);
	ocall_decent_tools_print_string_w(buf);
}

void Tools::GetSystemTime(time_t & timer)
{
	ocall_decent_tools_get_sys_time(&timer);
}

void Tools::GetSystemUtcTime(const time_t& timer, struct tm& outTime)
{
	ocall_decent_tools_get_sys_utc_time(&timer, &outTime);
}

#ifdef __GNUC__
extern "C" void __cxa_deleted_virtual(void) 
{
	abort();
}
#endif //__GNUC__
