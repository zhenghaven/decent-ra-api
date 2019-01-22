#include "Common.h"
#include "../Common/Common.h"

#include <array>
#include <ctime>

#include <mbedtls/platform_util.h>

using namespace Decent;

#ifdef _WIN32
#include <Windows.h>

namespace
{
	static constexpr std::array<int, 8> gsk_colorMap = 
	{
		0x0008 | 0x0004, //Red     = 0,
		0x0008 | 0x0002, //Green   = 1,
		0x0008 | 0x0006, //Yellow  = 2,
		0x0008 | 0x0001, //Blue    = 3,
		0x0008 | 0x0005, //Magenta = 4,
		0x0008 | 0x0003, //Cyan    = 5,
		0x0000 | 0x0007, //White   = 6,
		0x0000 | 0x0000, //Black   = 7,
//		0x0000 | 0x0000, //Default = 8,
	};

	static bool gsk_gotDefaultColor = false;

	static int gsk_foregroundColor = 0x0000 | 0x0007; //White
	static int gsk_backgroundColor = 0x0000 | 0x0000; //Black

	static void GetDefaultColor()
	{
		HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
		CONSOLE_SCREEN_BUFFER_INFO bufferInfo;
		GetConsoleScreenBufferInfo(hConsole, &bufferInfo);

		gsk_foregroundColor = bufferInfo.wAttributes & 0xFF;
		gsk_backgroundColor = (bufferInfo.wAttributes >> 4) & 0xFF;

		gsk_gotDefaultColor = true;
	}
}

void Tools::SetConsoleColor(ConsoleColors foreground, ConsoleColors background)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	
	if (!gsk_gotDefaultColor)
	{
		GetDefaultColor();
	}

	int fColor = foreground == ConsoleColors::Default ? gsk_foregroundColor : gsk_colorMap[static_cast<int>(foreground)];
	int bColor = background == ConsoleColors::Default ? gsk_backgroundColor : gsk_colorMap[static_cast<int>(background)];

	SetConsoleTextAttribute(hConsole, static_cast<WORD>(fColor | (bColor << 4)));
}

#else

namespace
{
	static constexpr std::array<int, 9> g_fColorMap =
	{
		31, //Red     = 0,
		32, //Green   = 1,
		33, //Yellow  = 2,
		34, //Blue    = 3,
		35, //Magenta = 4,
		36, //Cyan    = 5,
		37, //White   = 6,
		30, //Black   = 7,
		39, //Default = 8,
	};

	static constexpr std::array<int, 9> g_bColorMap =
	{
		41, //Red     = 0,
		42, //Green   = 1,
		43, //Yellow  = 2,
		44, //Blue    = 3,
		45, //Magenta = 4,
		46, //Cyan    = 5,
		47, //White   = 6,
		40, //Black   = 7,
		49, //Default = 8,
	};
}

void Tools::SetConsoleColor(ConsoleColors foreground, ConsoleColors background)
{
	printf("\033[%d;%dm", g_fColorMap[static_cast<int>(foreground)], g_bColorMap[static_cast<int>(background)]);
}

#endif // _WIN32

void Tools::Printf(const char * fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);
}

void Tools::LogInfo(const char* fmt, ...)
{
	SetConsoleColor(ConsoleColors::Green, ConsoleColors::Default);

	printf(" I: ");

	va_list ap;
	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);

	printf("\n");

	SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
}

void Tools::LogWarning(const char* file, const int line, const char* fmt, ...)
{
	SetConsoleColor(ConsoleColors::Yellow, ConsoleColors::Default);

	printf("File:%s\nline:%d\n", file, line);
	printf(" W: ");

	va_list ap;
	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);

	printf("\n");

	SetConsoleColor(ConsoleColors::Default, ConsoleColors::Default);
}

void Tools::GetSystemUtcTime(const time_t& timer, struct tm& outTime)
{
	mbedtls_platform_gmtime_r(&timer, &outTime);
}

void Tools::GetSystemTime(time_t& timer)
{
	std::time(&timer);
}
