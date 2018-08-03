#pragma once

#include <cstdio>

#include "Common.h"

/* OCall functions */
void ocall_print_string(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	* the input string to prevent buffer overflow.
	*/
	printf("%s", str);
}

void ocall_log_w(const char *file, int line, const char *str)
{
	SetConsoleColor(ConsoleColors::Yellow, ConsoleColors::Default);
	printf("File:%s\nline:%d\n", file, line);
	printf(" W: ");
	printf(str);
	printf("\n");
	SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
}