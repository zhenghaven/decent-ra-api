#pragma once

#include <ctime>
#include <memory>
#include <string>
#include <stdexcept>

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

#ifndef NDEBUG

#define PRINT_W(...) Decent::Tools::LogWarning(__FILE__, __LINE__, __VA_ARGS__);
#define LOGI(...) PRINT_I(__VA_ARGS__)
#define LOGW(...) PRINT_W(__VA_ARGS__)

#define EXCEPTION_ASSERT(X, Msg) if(!X) { throw std::logic_error(Msg); }

#else

#define PRINT_W(...) Decent::Tools::LogWarning("", 0, __VA_ARGS__);
#define LOGI(...) 
#define LOGW(...) 

#define EXCEPTION_ASSERT(X, Msg) 

#endif // !NDEBUG
