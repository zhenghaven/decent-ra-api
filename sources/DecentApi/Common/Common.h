#pragma once

#include <ctime>
#include <memory>
#include <string>

#ifndef NDEBUG

#define LOGI(...) Decent::Tools::LogInfo(__VA_ARGS__);
#define LOGW(...) Decent::Tools::LogWarning(__FILE__, __LINE__, __VA_ARGS__);

#else

#define LOGI(...) 
#define LOGW(...) 

#endif // !NDEBUG

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
