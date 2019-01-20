//#if ENCLAVE_PLATFORM_SGX

#include <cstdio>
#include <ctime>

#include "../Common.h"
#include "../../common/Common.h"

using namespace Decent::Tools;

extern "C" void ocall_decent_tools_print_string(const char *str)
{
	printf("%s", str);
}

extern "C" void ocall_decent_tools_print_string_i(const char *str)
{
	SetConsoleColor(ConsoleColors::Green, ConsoleColors::Default);
	printf("%s", str);
	SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
}

extern "C" void ocall_decent_tools_print_string_w(const char *str)
{
	SetConsoleColor(ConsoleColors::Yellow, ConsoleColors::Default);
	printf("%s", str);
	SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
}

extern "C" void ocall_decent_tools_get_sys_time(time_t* timer)
{
	std::time(timer);
}

extern "C" void ocall_decent_tools_get_sys_utc_time(const time_t* timer, tm* out_time)
{
	if (!timer || !out_time)
	{
		return;
	}

	GetSystemUtcTime(*timer, *out_time);
}

extern "C" void ocall_decent_tools_del_buf_char(char* ptr)
{
	delete[] ptr;
}

extern "C" void ocall_decent_tools_del_buf_uint8(uint8_t* ptr)
{
	delete[] ptr;
}

//#endif //ENCLAVE_PLATFORM_SGX
