#include <iostream>
#include <string>

#include <cstdio>

//#include <openssl/crypto.h>
#include <json/json.h>
#include <sgx_uae_service.h>
#include <curl/curl.h>

#include "../common_app/IAS/IASUtil.h"

#ifdef _MSC_VER

std::string GetSGXDeviceStatusStr(const sgx_device_status_t& sgx_device_status)
{
	switch (sgx_device_status) {
	case SGX_ENABLED:
		return "The platform is enabled for Intel SGX.";
	case SGX_DISABLED_REBOOT_REQUIRED:
		return "SGX device has been enabled. Please reboot your machine.";
	case SGX_DISABLED_LEGACY_OS:
		return "SGX device can't be enabled on an OS that doesn't support EFI interface.";
	case SGX_DISABLED:
		return "SGX is not enabled on this platform. More details are unavailable.";
	case SGX_DISABLED_SCI_AVAILABLE:
		return "SGX device can be enabled by a Software Control Interface.";
	case SGX_DISABLED_MANUAL_ENABLE:
		return "SGX device can be enabled manually in the BIOS setup.";
	case SGX_DISABLED_HYPERV_ENABLED:
		return "Detected an unsupported version of Windows* 10 with Hyper-V enabled.";
	case SGX_DISABLED_UNSUPPORTED_CPU:
		return "SGX is not supported by this CPU.";
	default:
		return "Unexpected error.";
	}
}

#endif

int main() {
	std::cout << "JsonCPP test:" << std::endl;
	std::cout << "================================" << std::endl;
	Json::Value obj;
	obj["A"] = 1;
	obj["B"] = 2;
	obj["C"] = 3;
	obj["D"] = 4;
	std::cout << obj.toStyledString() << std::endl;
	std::cout << "================================" << std::endl << std::endl << std::endl;

#ifdef _MSC_VER

	std::cout << "Intel SGX test:" << std::endl;
	std::cout << "================================" << std::endl;
	sgx_device_status_t sgx_device_status;
	sgx_status_t sgx_ret = sgx_enable_device(&sgx_device_status);
	if (sgx_ret != SGX_SUCCESS) 
	{
		std::cout << "Failed to get SGX device status." << std::endl << std::endl << std::endl;
	}
	else
	{
		std::cout << GetSGXDeviceStatusStr(sgx_device_status) << std::endl;
	}
	std::cout << "================================" << std::endl;

#endif
	
	CURL *hnd = curl_easy_init();

	curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt(hnd, CURLOPT_URL, "https://google.com");
	curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L);

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Cache-Control: no-cache");
	curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

	CURLcode ret = curl_easy_perform(hnd);

	curl_easy_cleanup(hnd);

	std::string s1;
	std::string s2;
	std::string s3;
	std::string s4;
	GetQuoteReport(s1, s2, s3, s4);

	std::cout << "Done! Enter anything to exit..." << std::endl;
	getchar();

	return 0;
}
