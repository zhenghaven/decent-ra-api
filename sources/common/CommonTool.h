#pragma once

#include <ctime>
#include <memory>

#ifdef ENCLAVE_ENVIRONMENT
#include "../common_enclave/Common.h"
#else
#include "../common_app/Common.h"
#endif // ENCLAVE_ENVIRONMENT

struct tm;

namespace Common
{
	void GetSystemTime(time_t& timer);
	void GetSystemUtcTime(const time_t& timer, struct tm& outTime);

	//Sgx does not suppot C++14 standard, thus, we need to define this manually.
	template<typename T, typename... Ts>
	std::unique_ptr<T> make_unique(Ts&&... params)
	{
		return std::unique_ptr<T>(new T(std::forward<Ts>(params)...));
	}
}
