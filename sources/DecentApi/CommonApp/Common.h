#pragma once

#include <cstdio>
#include <cassert>

namespace Decent
{
	namespace Tools
	{
		template<typename Base, typename T>
		inline bool instanceof(const T *ptr)
		{
			return dynamic_cast<const Base*>(ptr) != nullptr;
		}

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
