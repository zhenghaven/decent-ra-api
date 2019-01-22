#pragma once

#include <string>

#include <sgx_error.h>
#include <sgx_capable.h>

namespace Decent
{
	namespace Sgx
	{
		std::string GetErrorMessage(const sgx_status_t ret);

		std::string GetDeviceStatusStr(const sgx_device_status_t ret);

		sgx_status_t GetDeviceStatus(sgx_device_status_t& res);
	}
}
