#ifndef NOMINMAX
# define NOMINMAX
#endif

#include <iostream>
#include <string>

#include <cstdio>

//#include <openssl/crypto.h>
#include <json/json.h>
#include <sgx_uae_service.h>
#include <curl/curl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <cppcodec/base64_rfc4648.hpp>

#include "../common_app/SGX/IAS/IASUtil.h"
#include "../common/SGX/ias_report_cert.h"
#include "../common/OpenSSLTools.h"

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

	int sslRes = 0;

	std::vector<X509*> certs;
	LoadX509CertsFromStr(certs, IAS_REPORT_CERT);
	X509* iasCert = certs[0];

	std::string s1 = "{\r\n\"isvEnclaveQuote\": \"AgABAPAKAAAHAAYAAAAAAN0WQP4NKMmoswWvTU52WL4AAAAAAAAAAAAAAAAAAAAABQUCBAECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAADHQElNZvJ5D+ILaWmNeFeIj2MyOXBG1pUSQdE428ixtAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwECALZcM+G8O0Ys+P0oIWxtVbWdSF9QCxaucw3ak8gwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAABFPePLzujWuMPeJyvsNK8oFfwLdAWBDyKGajC5xhNzJw/bLsveZ8HtfK2LZnrU5PLEZkWBn2Y1awZ6FBpkHed7PRLHtbRcOSmapOpPnKot7yqBgpyotsRXvNaF1zDNmIzk6AQeaLdKl4Tlj+zbuAdF+LSCRHqbBTEcLFimI/lXEjgIimbmVXrza5iHQw0TDy/ayl1y1X0EfML6FGgzEI9dcMAnXTPxGRzoYBxmjuAWF8vdNxRfmJ3N++8zGwNQRiip4fzfx/ojfak/R4PKVILsR0N8FFcREg3gBOXSibI238b2FHEYCoxFcBfLMS+bHkPLRwzSERhxUP/jOFWTLp5lPRjbgEtDvcPoi8qlzkVGzpsrmWA8w473XjnoiuhRW+PjGtNo59M1eh4VEHmgBAAC49nn3pD9+jxjfhbDAhMFeZR62Be61dmKV/JyDlyZ4IFLxcy26soHPzWa0ZvTulmTW5MqRDyZeSe0vQ7Pkz+IuUCf2jsxB6ktBiSZpGYBWqtI7V5KKbViFxdpVbU+3kxev+YBgo0jxUiCXWA2aXkmows9vg65t2oezendW4vxUklRMPQhH+MRV0eRaFyFtXiXSd4jZQ2/lKvMgYz/wIizITVSk8zt9JxaOI3RsfFgaRslSvCbMgsoagTsedKIxpwImkg6e/G8eAXlQ8S51NsIsjwgoBH8/e8H8AhBF+PdH7emWrJIudwdL3/QZF6eK+PI5d0dfKTBdv0HTR8n0AGY5wW2IBTEUQrGbTrhbG9JVxfqc3ykkgF9ZiAXilvNx8iLRTvVVV8Gtzp5t8w/fYiL8YO68gJbE+Z+Vm6AHpdj4rQNm4OowNVTgNpHPk3J6EnUII7hikqEc+VRCYLmg3/Y472YTmY3BXARp/xfRFJmaTpujQ4JHxTLs\"\r\n}";
	std::string s2;
	std::string s3;
	std::string s4;
	IASUtil::GetQuoteReport(s1, s2, s3, s4, IASUtil::GetDefaultCertPath(), IASUtil::GetDefaultKeyPath());

	LoadX509CertsFromStr(certs, s4);

	bool certVerRes = VerifyIasReportCert(iasCert, certs);

	std::vector<uint8_t> buffer1 = cppcodec::base64_rfc4648::decode<std::vector<uint8_t>, std::string>(s3);

	bool signVerRes = VerifyIasReportSignature(s2, buffer1, certs[0]);

	FreeX509Cert(&iasCert);
	FreeX509Cert(certs);

	std::cout << "Done! Enter anything to exit..." << std::endl;
	getchar();

	return 0;
}
