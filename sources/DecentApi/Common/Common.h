#pragma once

#include <ctime>
#include <memory>
#include <string>

namespace Decent
{
	namespace Tools
	{
		void GetSystemTime(time_t& timer);
		void GetSystemUtcTime(const time_t& timer, struct tm& outTime);

		void Printf(const char* fmt, ...);
		void LogInfo(const char* fmt, ...);
		void LogWarning(const char* file, const int line, const char* fmt, ...);
	}
}

#define PRINT_I(...) Decent::Tools::LogInfo(__VA_ARGS__);
#define PRINT_W(...) Decent::Tools::LogWarning(__FILE__, __LINE__, __VA_ARGS__);

#ifndef NDEBUG

#define LOGI(...) PRINT_I(__VA_ARGS__)
#define LOGW(...) PRINT_W(__VA_ARGS__)

#else

#define LOGI(...) 
#define LOGW(...) 

#endif // !NDEBUG
