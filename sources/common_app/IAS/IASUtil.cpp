#include "IASUtil.h"

#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cctype>
//#include <cstdio>

#include <cppcodec/hex_lower.hpp>

#include <curl/curl.h>

#include "../FileSystemUtil.h"

//namespace
//{
//	const std::string IAS_URL_BASE = "https://test-as.sgx.trustedservices.intel.com:443";
//	const std::string IAS_URL_SIGRL = IAS_URL_BASE + "/attestation/sgx/v2/sigrl/";
//	const std::string IAS_URL_REPORT = IAS_URL_BASE + "/attestation/sgx/v2/report";
//}

namespace
{
	typedef size_t(*cUrlContentCallBack)(char*, size_t, size_t, void*);
	typedef size_t(*cUrlHeaderCallBack)(char*, size_t, size_t, void*);

	cUrlContentCallBack g_contentCallbackStatic = [](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t
	{
		cUrlContentCallBackFunc* callbackFunc = static_cast<cUrlContentCallBackFunc*>(userdata);
		if (!callbackFunc)
		{
			return 0;
		}
		return (*callbackFunc)(ptr, size, nmemb, nullptr);
	};

	cUrlHeaderCallBack g_headerCallbackStatic = [](char *ptr, size_t size, size_t nitems, void *userdata)->size_t
	{
		cUrlHeaderCallBackFunc* callbackFunc = static_cast<cUrlHeaderCallBackFunc*>(userdata);
		if (!callbackFunc)
		{
			return 0;
		}
		return (*callbackFunc)(ptr, size, nitems, nullptr);
	};
}

// trim from start (in place)
static inline std::string& ltrim(std::string &s)
{
	s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](char ch) 
	{
		return !std::isspace(ch);
	}));

	return s;
}

// trim from end (in place)
static inline std::string& rtrim(std::string &s)
{
	s.erase(std::find_if(s.rbegin(), s.rend(), [](char ch)
	{
		return !std::isspace(ch);
	}).base(), s.end());

	return s;
}

static std::string GetGIDBigEndianStr(const sgx_epid_group_id_t& gid)
{
	std::vector<uint8_t> gidcpy(sizeof(sgx_epid_group_id_t), 0);
	std::memcpy(&gidcpy[0], &gid, gidcpy.size());
	std::reverse(gidcpy.begin(), gidcpy.end());

	return cppcodec::hex_lower::encode(gidcpy);
}

bool GetRevocationList(const sgx_epid_group_id_t& gid, std::string & outRevcList, const std::string& certPath, const std::string& keyPath)
{
	bool res = true;

#ifdef DEBUG
	const std::string iasURL = GetIasUrlHostDev() + GetIasUrlSigRlPath() + GetGIDBigEndianStr(gid);
#else
	const std::string iasURL = GetIasUrlHostRelease() + GetIasUrlSigRlPath() + GetGIDBigEndianStr(gid);
#endif // DEBUG

	outRevcList = "";
	std::string requestId;

	cUrlContentCallBackFunc contentCallback = [&outRevcList](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t
	{
		outRevcList = std::string(ptr, size * nmemb);
		return size * nmemb;
	};

	cUrlHeaderCallBackFunc headerCallback = [&requestId](char *ptr, size_t size, size_t nitems, void *userdata)->size_t
	{
		static std::string tmp;
		tmp = std::string(ptr, size * nitems);
		if (tmp.find("request-id") != std::string::npos)
		{
			requestId = tmp.substr(tmp.find_first_of(':') + 1);
			rtrim(ltrim(requestId));
		}
		return size * nitems;
	};

	CURL *hnd = curl_easy_init();

	curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
	curl_easy_setopt(hnd, CURLOPT_URL, iasURL.c_str());
	curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(hnd, CURLOPT_SSLCERT, GetDefaultCertPath().c_str());
	curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM");
	curl_easy_setopt(hnd, CURLOPT_SSLKEY, GetDefaultKeyPath().c_str());
	curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM");
	curl_easy_setopt(hnd, CURLOPT_HEADERFUNCTION, g_headerCallbackStatic);
	curl_easy_setopt(hnd, CURLOPT_HEADERDATA, &headerCallback);
	curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, g_contentCallbackStatic);
	curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &contentCallback);

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Cache-Control: no-cache");
	curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);

	CURLcode ret = curl_easy_perform(hnd);

	long response_code;
	if (ret == CURLE_OK) {
		curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &response_code);
	}

	curl_easy_cleanup(hnd);

	return res;
}

bool GetRevocationList(const sgx_epid_group_id_t & gid, std::string & outRevcList)
{
	return GetRevocationList(gid, outRevcList, GetDefaultCertPath(), GetDefaultKeyPath());
}

std::string GetDefaultIasDirPath()
{
	return GetKnownFolderPath(KnownFolderType::Home).append("SGX_IAS").string();
}

std::string GetDefaultCertPath()
{
	return GetKnownFolderPath(KnownFolderType::Home).append("SGX_IAS").append("client.crt").string();
}

std::string GetDefaultKeyPath()
{
	return GetKnownFolderPath(KnownFolderType::Home).append("SGX_IAS").append("client.pem").string();
}

std::string GetDefaultRsaKeyPath()
{
	return GetKnownFolderPath(KnownFolderType::Home).append("SGX_IAS").append("client.key").string();
}
