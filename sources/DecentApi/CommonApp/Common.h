#pragma once

#include <cstdio>
#include <cassert>

namespace Decent
{
	namespace Tools
	{
		enum class ConsoleColors
		{
			Red     = 0,
			Green   = 1,
			Yellow  = 2,
			Blue    = 3,
			Magenta = 4,
			Cyan    = 5,
			White   = 6,
			Black   = 7,
			Default = 8,
		};

		void SetConsoleColor(ConsoleColors foreground, ConsoleColors background);
	}
}
