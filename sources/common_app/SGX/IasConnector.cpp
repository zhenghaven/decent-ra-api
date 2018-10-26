#include "IasConnector.h"

#ifndef NOMINMAX
# define NOMINMAX
#endif

#include <cctype>

#include <vector>
#include <functional>
#include <algorithm>

#include <sgx_quote.h>
#include <sgx_key_exchange.h>

#include <json/json.h>
#include <curl/curl.h>
#include <cppcodec/hex_lower.hpp>

#include "../../common/DataCoding.h"
#include "../../common/SGX/IasConnector.h"

#include "../FileSystemUtil.h"

#ifdef SIMULATING_ENCLAVE
#include <json/json.h>
#include <sgx_report.h>
#include "../../common/DataCoding.h"
#endif // SIMULATING_ENCLAVE

namespace
{
	static const fs::path gsk_defaultIasPath = GetKnownFolderPath(KnownFolderType::Home).append("SGX_IAS");

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

constexpr char const IASConnector::sk_iasUrl[];
constexpr char const IASConnector::sk_iasSigRlPath[];
constexpr char const IASConnector::sk_iasReportPath[];
const std::string IASConnector::sk_iasUrlStr = sk_iasUrl;
const std::string IASConnector::sk_defaultCertPath = fs::path(gsk_defaultIasPath).append("client.crt").string();
const std::string IASConnector::sk_defaultKeyPath = fs::path(gsk_defaultIasPath).append("client.pem").string();
const std::string IASConnector::sk_defaultRsaKeyPath = fs::path(gsk_defaultIasPath).append("client.key").string();

bool IASConnector::GetRevocationList(const sgx_epid_group_id_t & gid, const std::string & certPath, const std::string & keyPath, 
	std::string & outRevcList)
{
	const std::string iasURL = sk_iasUrlStr + sk_iasSigRlPath + GetGIDBigEndianStr(gid);

	outRevcList.resize(0);
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

bool IASConnector::GetQuoteReport(const std::string & jsonReqBody, const std::string & certPath, const std::string & keyPath, 
	std::string & outReport, std::string & outSign, std::string & outCert)
{
	const std::string iasURL = sk_iasUrlStr + sk_iasReportPath;

	outReport.resize(0);
	outSign.resize(0);
	outCert.resize(0);
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
	//reportJson["pseManifestStatus"] = "OK";
	//reportJson["pseManifestHash"] = "7563016AF9AE650FCAE9D94FBEE7DA39264A5C6C2B85CCDA8337D208BA17709E";
	reportJson["nonce"] = jsonRoot["nonce"].asString();
	reportJson["isvEnclaveQuoteBody"] = quoteB64;

	outReport = reportJson.toStyledString();

	return true;
#endif // !SIMULATING_ENCLAVE
}

IASConnector::IASConnector() :
	IASConnector(sk_defaultCertPath, sk_defaultKeyPath)
{
}

IASConnector::IASConnector(const std::string & certPath, const std::string & keyPath) :
	m_certPath(certPath),
	m_keyPath(keyPath)
{
}

IASConnector::~IASConnector()
{
}

bool IASConnector::GetRevocationList(const sgx_epid_group_id_t & gid, std::string & outRevcList) const
{
	return IASConnector::GetRevocationList(gid, m_certPath, m_keyPath, outRevcList);
}

bool IASConnector::GetQuoteReport(const sgx_ra_msg3_t& msg3, const size_t msg3Size, const std::string& nonce, const bool pseEnabled, 
	std::string & outReport, std::string & outSign, std::string & outCert) const
{
	const sgx_quote_t& quote = reinterpret_cast<const sgx_quote_t&>(msg3.quote);
	Json::Value iasReqRoot;
	iasReqRoot["isvEnclaveQuote"] = SerializeStruct(msg3.quote, msg3Size - sizeof(sgx_ra_msg3_t));
	iasReqRoot["nonce"] = nonce;
	if (pseEnabled)
	{
		iasReqRoot["pseManifest"] = SerializeStruct(msg3.ps_sec_prop);
	}
	return GetQuoteReport(iasReqRoot.toStyledString(), m_certPath, m_keyPath, outReport, outSign, outCert);
}

bool StaticIasConnector::GetRevocationList(const void* const connectorPtr, const sgx_epid_group_id_t& gid, std::string& outRevcList)
{
	if (!connectorPtr)
	{
		return false;
	}

	return reinterpret_cast<const IASConnector*>(connectorPtr)->GetRevocationList(gid, outRevcList);
}

bool StaticIasConnector::GetQuoteReport(const void* const connectorPtr, const sgx_ra_msg3_t& msg3, const size_t msg3Size, const std::string& nonce, const bool pseEnabled, std::string& outReport, std::string& outSign, std::string& outCert)
{
	if (!connectorPtr)
	{
		return false;
	}

	return reinterpret_cast<const IASConnector*>(connectorPtr)->GetQuoteReport(msg3, msg3Size, nonce, pseEnabled, outReport, outSign, outCert);
}

extern "C" int ocall_ias_get_revoc_list(const void* const connector_ptr, const sgx_epid_group_id_t* gid, char** outRevcList, size_t* outSize)
{
	if (!connector_ptr || !gid ||
		!outRevcList || !outSize)
	{
		return false;
	}

	*outRevcList = nullptr;

	std::string revcList;
	if (!StaticIasConnector::GetRevocationList(connector_ptr, *gid, revcList))
	{
		return false;
	}

	*outRevcList = new char[revcList.size()];
	*outSize = revcList.size();
	std::memcpy(*outRevcList, revcList.data(), revcList.size());
	return true;
}

extern "C" int ocall_ias_get_quote_report(const void* const connector_ptr, const sgx_ra_msg3_t* msg3, const size_t msg3_size,
	const char* nonce, const int pse_enabled,
	char** out_report, size_t* report_size,
	char** out_sign, size_t* sign_size,
	char** out_cert, size_t* cert_size)
{
	if (!connector_ptr || !msg3 || !msg3_size || !nonce ||
		!out_report || !report_size ||
		!out_sign || !sign_size ||
		!out_cert || !cert_size)
	{
		return false;
	}

	*out_report = *out_sign = *out_cert = nullptr;

	std::string report;
	std::string sign;
	std::string cert;
	if (!StaticIasConnector::GetQuoteReport(connector_ptr, *msg3, msg3_size, nonce, pse_enabled == 1, report, sign, cert))
	{
		return false;
	}

	*out_report = new char[report.size()];
	*report_size = report.size();
	std::memcpy(*out_report, report.data(), report.size());

	*out_sign = new char[sign.size()];
	*sign_size = sign.size();
	std::memcpy(*out_sign, sign.data(), sign.size());

	*out_cert = new char[cert.size()];
	*cert_size = cert.size();
	std::memcpy(*out_cert, cert.data(), cert.size());

	return true;
}
