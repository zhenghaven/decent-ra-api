#pragma once

#include <cstdio>

#include "Common.h"

/* OCall functions */
extern "C" void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	* the input string to prevent buffer overflow.
	*/
	printf("%s", str);
}

extern "C" void ocall_log_w(const char *file, int line, const char *str)
{
	SetConsoleColor(ConsoleColors::Yellow, ConsoleColors::Default);
	printf("File:%s\nline:%d\n", file, line);
	printf(" W: ");
	printf(str);
	printf("\n");
	SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
}

extern "C" void ocall_log_e(const char *file, int line, const char *str)
{
	SetConsoleColor(ConsoleColors::Red, ConsoleColors::Default);
	printf("File:%s\nline:%d\n", file, line);
	printf(" E: ");
	printf(str);
	printf("\n");
	SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
	assert(false);
}