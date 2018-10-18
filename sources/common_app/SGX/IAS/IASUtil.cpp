#include "IASUtil.h"

#include <vector>
#include <algorithm>
#include <cctype>
#include <functional>

#include <cppcodec/hex_lower.hpp>

#include <curl/curl.h>

#include "../../FileSystemUtil.h"

#ifdef SIMULATING_ENCLAVE
#include <json/json.h>
#include <sgx_report.h>
#include "../../../common/DataCoding.h"
#endif // SIMULATING_ENCLAVE

using namespace IASUtil;

namespace
{
	typedef std::function<size_t(char*, size_t, size_t, void*)> cUrlContentCallBackFunc;
	typedef std::function<size_t(char*, size_t, size_t, void*)> cUrlHeaderCallBackFunc;

	static size_t ContentCallbackStatic(char *ptr, size_t size, size_t nmemb, void *userdata)
	{
		cUrlContentCallBackFunc* callbackFunc = static_cast<cUrlContentCallBackFunc*>(userdata);
		if (!callbackFunc)
		{
			return 0;
		}
		return (*callbackFunc)(ptr, size, nmemb, nullptr);
	}

	static size_t HeaderCallbackStatic(char *ptr, size_t size, size_t nitems, void *userdata)
	{
		cUrlHeaderCallBackFunc* callbackFunc = static_cast<cUrlHeaderCallBackFunc*>(userdata);
		if (!callbackFunc)
		{
			return 0;
		}
		return (*callbackFunc)(ptr, size, nitems, nullptr);
	}

	// trim from start (in place)
	static std::string& ltrim(std::string &s)
	{
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](char ch) 
		{
			return !std::isspace(ch);
		}));

		return s;
	}

	// trim from end (in place)
	static std::string& rtrim(std::string &s)
	{
		s.erase(std::find_if(s.rbegin(), s.rend(), [](char ch)
		{
			return !std::isspace(ch);
		}).base(), s.end());

		return s;
	}

	static std::string& ParseHeaderLine(std::string& s)
	{
		s = s.substr(s.find_first_of(':') + 1);
		rtrim(ltrim(s));
		return s;
	}

	static std::string GetGIDBigEndianStr(const sgx_epid_group_id_t& gid)
	{
		const uint8_t(&gidRef)[4] = gid;
		std::vector<uint8_t> gidcpy(std::rbegin(gidRef), std::rend(gidRef));

		return cppcodec::hex_lower::encode(gidcpy);
	}
}

bool IASUtil::GetRevocationList(const sgx_epid_group_id_t& gid, std::string & outRevcList, const std::string& certPath, const std::string& keyPath)
{
	const std::string iasURL = GetIasUrlHost() + GetIasUrlSigRlPath() + GetGIDBigEndianStr(gid);

	outRevcList = "";
	std::string requestId;

#ifndef SIMULATING_ENCLAVE
	cUrlContentCallBackFunc contentCallback = [&outRevcList](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t
	{
		outRevcList = std::string(ptr, size * nmemb);
		return size * nmemb;
	};

	cUrlHeaderCallBackFunc headerCallback = [&requestId](char *ptr, size_t size, size_t nitems, void *userdata) -> size_t
	{
		static std::string tmp;
		tmp = std::string(ptr, size * nitems);
		if (tmp.find("request-id") == 0)
		{
			requestId = ParseHeaderLine(tmp);
		}
		return size * nitems;
	};

	CURL *hnd = curl_easy_init();
	curl_slist *headers = curl_slist_append(nullptr, "Cache-Control: no-cache");
	long response_code = 0;

	if (hnd == nullptr ||
		headers == nullptr ||
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET") != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_URL, iasURL.c_str()) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSLCERT, certPath.c_str()) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM") != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSLKEY, keyPath.c_str()) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM") != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_HEADERFUNCTION, &HeaderCallbackStatic) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_HEADERDATA, &headerCallback) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, &ContentCallbackStatic) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &contentCallback) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
		curl_easy_perform(hnd) != CURLE_OK ||
		curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK)
	{
		curl_slist_free_all(headers);
		curl_easy_cleanup(hnd);
		return false;
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(hnd);

	return response_code == 200;
#else
	return true;
#endif // !SIMULATING_ENCLAVE
}

bool IASUtil::GetQuoteReport(const std::string & jsonReqBody, std::string & outReport, std::string & outSign, std::string & outCert, const std::string & certPath, const std::string & keyPath)
{
	const std::string iasURL = GetIasUrlHost() + GetIasUrlReportPath();

	outReport = "";
	std::string requestId;

#ifndef SIMULATING_ENCLAVE
	cUrlContentCallBackFunc contentCallback = [&outReport](char *ptr, size_t size, size_t nmemb, void *userdata) -> size_t
	{
		outReport = std::string(ptr, size * nmemb);
		return size * nmemb;
	};

	cUrlHeaderCallBackFunc headerCallback = [&requestId, &outSign, &outCert](char *ptr, size_t size, size_t nitems, void *userdata) -> size_t
	{
		static std::string tmp;
		tmp = std::string(ptr, size * nitems);
		if (tmp.find("request-id") == 0)
		{
			requestId = ParseHeaderLine(tmp);
		}
		if (tmp.find("x-iasreport-signature") == 0)
		{
			outSign = ParseHeaderLine(tmp);
		}
		if (tmp.find("x-iasreport-signing-certificate") == 0)
		{
			outCert = ParseHeaderLine(tmp);
		}
		return size * nitems;
	};

	CURL *hnd = curl_easy_init();
	curl_slist *headers = curl_slist_append(nullptr, "Cache-Control: no-cache");
	long response_code = 0;

	if (hnd == nullptr ||
		headers == nullptr ||
		(headers = curl_slist_append(headers, "Content-Type: application/json")) == nullptr ||
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST") != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_URL, iasURL.c_str()) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSLCERT, certPath.c_str()) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSLCERTTYPE, "PEM") != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSLKEY, keyPath.c_str()) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSLKEYTYPE, "PEM") != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_HEADERFUNCTION, &HeaderCallbackStatic) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_HEADERDATA, &headerCallback) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, &ContentCallbackStatic) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &contentCallback) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_POSTFIELDS, jsonReqBody.c_str()) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
		curl_easy_perform(hnd) != CURLE_OK ||
		curl_easy_getinfo(hnd, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK)
	{
		curl_slist_free_all(headers);
		curl_easy_cleanup(hnd);
		return false;
	}
	
	{
		int outLen = 0;
		char* outStr = curl_easy_unescape(hnd, outCert.c_str(), static_cast<int>(outCert.length()), &outLen);
		outCert = std::string(outStr, outLen);
		std::free(outStr);
	}

	curl_slist_free_all(headers);
	curl_easy_cleanup(hnd);

	return response_code == 200;

#else
	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(jsonReqBody.c_str(), jsonReqBody.c_str() + jsonReqBody.size(), &jsonRoot, &errStr);

	std::vector<uint8_t> buffer;
	DeserializeStruct(buffer, jsonRoot["isvEnclaveQuote"].asString());
	std::string quoteB64 = SerializeStruct(buffer.data(), sizeof(sgx_quote_t) - sizeof(sgx_quote_t::signature_len));

	Json::Value reportJson;

	reportJson["id"] = "165171271757108173876306223827987629752";
	reportJson["timestamp"] = "2015-09-29T10:07:26.711023";
	reportJson["isvEnclaveQuoteStatus"] = "OK";
	reportJson["nonce"] = jsonRoot["nonce"].asString();
	reportJson["isvEnclaveQuoteBody"] = quoteB64;

	outReport = reportJson.toStyledString();

	return true;
#endif // !SIMULATING_ENCLAVE
}

std::string IASUtil::GetDefaultIasDirPath()
{
	return GetKnownFolderPath(KnownFolderType::Home).append("SGX_IAS").string();
}

std::string IASUtil::GetDefaultCertPath()
{
	return GetKnownFolderPath(KnownFolderType::Home).append("SGX_IAS").append("client.crt").string();
}

std::string IASUtil::GetDefaultKeyPath()
{
	return GetKnownFolderPath(KnownFolderType::Home).append("SGX_IAS").append("client.pem").string();
}

std::string IASUtil::GetDefaultRsaKeyPath()
{
	return GetKnownFolderPath(KnownFolderType::Home).append("SGX_IAS").append("client.key").string();
}
