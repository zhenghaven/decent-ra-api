#include "EnclaveUtil.h"

#include <map>
#include <exception>

#include <sgx_uae_service.h>

#include "../../Common/Common.h"

using namespace Decent;

namespace
{
	static const std::map<sgx_device_status_t, std::string> g_sgxDeviceStatus =
	{
		std::pair<sgx_device_status_t, std::string>(SGX_ENABLED, "Enabled"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_REBOOT_REQUIRED, "A reboot is required to finish enabling SGX"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_LEGACY_OS, "SGX is disabled and a Software Control Interface is not available to enable it"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED, "SGX is not enabled on this platform. More details are unavailable."),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_SCI_AVAILABLE, "SGX is disabled, but a Software Control Interface is available to enable it"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_MANUAL_ENABLE, "SGX is disabled, but can be enabled manually in the BIOS setup"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_HYPERV_ENABLED, "Detected an unsupported version of Windows* 10 with Hyper-V enabled"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_UNSUPPORTED_CPU, "SGX is not supported by this CPU"),
	};
}

std::string Sgx::GetDeviceStatusStr(const sgx_device_status_t ret)
{
	auto it = g_sgxDeviceStatus.find(ret);
	if (it == g_sgxDeviceStatus.cend())
	{
		LOGW("Error: Cannot find the status string specified!");
		throw std::runtime_error("Error: Cannot find the status string specified!");
	}
	return it->second;
}

sgx_status_t Sgx::GetDeviceStatus(sgx_device_status_t & res)
{
#ifdef _WIN32
	return sgx_enable_device(&res);
#else
    LOGW("Temporary fix for this function. Need to be fixed later.");
	res = SGX_ENABLED;
    return SGX_SUCCESS;
#endif
}
