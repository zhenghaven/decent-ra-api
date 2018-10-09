#pragma once

#include <ctime>

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
}
