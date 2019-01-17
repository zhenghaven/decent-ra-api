//#if ENCLAVE_PLATFORM_SGX

#include <cstdio>

#include "../Common.h"

extern "C" void ocall_print_string(const char *str)
{
	printf("%s", str);
}

extern "C" void ocall_print_string_w(const char *str)
{
	SetConsoleColor(ConsoleColors::Yellow, ConsoleColors::Default);
	printf("%s", str);
	SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
}

extern "C" void ocall_print_string_e(const char *str)
{
	SetConsoleColor(ConsoleColors::Red, ConsoleColors::Default);
	printf("%s", str);
	SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
}

//#endif //ENCLAVE_PLATFORM_SGX
