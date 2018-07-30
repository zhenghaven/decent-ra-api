#include "Common.h"

#include <vector>

#ifdef _WIN32
#include <Windows.h>

namespace
{
	std::vector<int> g_colorMap = 
	{
		0x0008 | 0x0004, //Red = 0,
		0x0008 | 0x0002, //Green = 1,
		0x0008 | 0x0006, //Yellow = 2,
		0x0008 | 0x0001, //Blue = 3,
		0x0008 | 0x0005, //Magenta = 4,
		0x0008 | 0x0003, //Cyan = 5,
		0x0000 | 0x0007, //White = 6,
		0x0000 | 0x0000, //Black = 7,
//		0x0000 | 0x0000, //Default = 8,
	};

	bool gotDefaultColor = false;

	int foregroundColor = 0x0000 | 0x0007; //White
	int backgroundColor = 0x0000 | 0x0000; //Black
}

void GetDefaultColor()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO bufferInfo;
	GetConsoleScreenBufferInfo(hConsole, &bufferInfo);

	foregroundColor = bufferInfo.wAttributes & 0xFF;
	backgroundColor = (bufferInfo.wAttributes >> 4) & 0xFF;

	gotDefaultColor = true;
}

void SetConsoleColor(ConsoleColors foreground, ConsoleColors background)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	
	if (!gotDefaultColor)
	{
		GetDefaultColor();
	}

	int fColor = foreground == ConsoleColors::Default ? foregroundColor : g_colorMap[static_cast<int>(foreground)];
	int bColor = background == ConsoleColors::Default ? backgroundColor : g_colorMap[static_cast<int>(background)];

	SetConsoleTextAttribute(hConsole, static_cast<WORD>(fColor | (bColor << 4)));
}

#else

std::vector<int> g_fColorMap =
{
	31, //Red = 0,
	32, //Green = 1,
	33, //Yellow = 2,
	34, //Blue = 3,
	35, //Magenta = 4,
	36, //Cyan = 5,
	37, //White = 6,
	30, //Black = 7,
	39, //Default = 8,
};

std::vector<int> g_bColorMap =
{
	41, //Red = 0,
	42, //Green = 1,
	43, //Yellow = 2,
	44, //Blue = 3,
	45, //Magenta = 4,
	46, //Cyan = 5,
	47, //White = 6,
	40, //Black = 7,
	49, //Default = 8,
};

void SetConsoleColor(ConsoleColors foreground, ConsoleColors background)
{
	printf("\033[%d;%dm", g_fColorMap[static_cast<int>(foreground)], g_bColorMap[static_cast<int>(background)]);
}

#endif // _WIN32
