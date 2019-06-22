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

#include "../../Common/Tools/DataCoding.h"
#include "../../Common/SGX/IasConnector.h"

#ifdef SIMULATING_ENCLAVE
#include "../Net/TCPConnection.h"
#include "../../Common/Net/RpcParser.h"
#endif // SIMULATING_ENCLAVE

using namespace Decent::Ias;
using namespace Decent::Tools;

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

constexpr char const Connector::sk_iasUrl[];
constexpr char const Connector::sk_pathSigRl[];
constexpr char const Connector::sk_pathReport[];

constexpr char const Connector::sk_headerLabelSubKey[];
constexpr char const Connector::sk_headerLabelReqId[];
constexpr char const Connector::sk_headerLabelSign[];
constexpr char const Connector::sk_headerLabelCert[];

bool Connector::GetRevocationList(const sgx_epid_group_id_t & gid, const std::string& subscriptionKey, std::string & outRevcList)
{
	static const std::string s_iasSigRlRootPath = std::string(sk_iasUrl) + sk_pathSigRl;

	const std::string gidBigEndStr = GetGIDBigEndianStr(gid);
	const std::string iasSigRlFullPath = s_iasSigRlRootPath + gidBigEndStr;

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
		if (tmp.find(sk_headerLabelReqId) == 0)
		{
			requestId = ParseHeaderLine(tmp);
		}
		return size * nitems;
	};

	std::string headerSubKey = std::string(sk_headerLabelSubKey) + ": " + subscriptionKey;

	CURL *hnd = curl_easy_init();
	curl_slist *headers = curl_slist_append(nullptr, "Cache-Control: no-cache");
	long response_code = 0;

	if (hnd == nullptr ||
		headers == nullptr ||
		(headers = curl_slist_append(headers, headerSubKey.c_str() )) == nullptr ||
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET") != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_URL, iasSigRlFullPath.c_str()) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK ||
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

	Net::TCPConnection iasSimConnection("127.0.0.1", 57720);

	iasSimConnection.SendPack("SigRl");
	iasSimConnection.SendPack(gidBigEndStr);

	std::vector<uint8_t> resp;
	iasSimConnection.ReceivePack(resp);

	Net::RpcParser iasSimRet(std::move(resp));

	outRevcList = iasSimRet.GetStringArg();

	return true;
#endif // !SIMULATING_ENCLAVE
}

bool Connector::GetQuoteReport(const std::string & jsonReqBody, const std::string& subscriptionKey,
	std::string & outReport, std::string & outSign, std::string & outCert)
{
	static const std::string s_iasReportFullPath = std::string(sk_iasUrl) + sk_pathReport;

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
		if (tmp.find(sk_headerLabelReqId) == 0)
		{
			requestId = ParseHeaderLine(tmp);
		}
		if (tmp.find(sk_headerLabelSign) == 0)
		{
			outSign = ParseHeaderLine(tmp);
		}
		if (tmp.find(sk_headerLabelCert) == 0)
		{
			outCert = ParseHeaderLine(tmp);
		}
		return size * nitems;
	};

	std::string headerSubKey = std::string(sk_headerLabelSubKey) + ": " + subscriptionKey;

	CURL *hnd = curl_easy_init();
	curl_slist *headers = curl_slist_append(nullptr, "Cache-Control: no-cache");
	long response_code = 0;

	if (hnd == nullptr ||
		headers == nullptr ||
		(headers = curl_slist_append(headers, "Content-Type: application/json")) == nullptr ||
		(headers = curl_slist_append(headers, headerSubKey.c_str() )) == nullptr ||
		curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "POST") != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_URL, s_iasReportFullPath.c_str()) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_SSL_VERIFYPEER, 0L) != CURLE_OK ||
		curl_easy_setopt(hnd, CURLOPT_FOLLOWLOCATION, 1L) != CURLE_OK ||
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

	Net::TCPConnection iasSimConnection("127.0.0.1", 57720);

	iasSimConnection.SendPack("Report");
	iasSimConnection.SendPack(jsonReqBody);

	std::vector<uint8_t> resp;
	iasSimConnection.ReceivePack(resp);

	Net::RpcParser iasSimRet(std::move(resp));

	outReport = iasSimRet.GetStringArg();
	outSign = iasSimRet.GetStringArg();
	outCert = iasSimRet.GetStringArg();

	return true;
#endif // !SIMULATING_ENCLAVE
}

Connector::Connector(const std::string& subscriptionKey) :
	m_subscriptionKey(subscriptionKey)
{
}

Connector::~Connector()
{
}

bool Connector::GetRevocationList(const sgx_epid_group_id_t & gid, std::string & outRevcList) const
{
	return Connector::GetRevocationList(gid, m_subscriptionKey, outRevcList);
}

bool Connector::GetQuoteReport(const sgx_ra_msg3_t& msg3, const size_t msg3Size, const std::string& nonce, const bool pseEnabled, 
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
	return GetQuoteReport(iasReqRoot.toStyledString(), m_subscriptionKey, outReport, outSign, outCert);
}

bool StatConnector::GetRevocationList(const void* const connectorPtr, const sgx_epid_group_id_t& gid, std::string& outRevcList)
{
	if (!connectorPtr)
	{
		return false;
	}

	return reinterpret_cast<const Connector*>(connectorPtr)->GetRevocationList(gid, outRevcList);
}

bool StatConnector::GetQuoteReport(const void* const connectorPtr, const sgx_ra_msg3_t& msg3, const size_t msg3Size, const std::string& nonce, const bool pseEnabled, std::string& outReport, std::string& outSign, std::string& outCert)
{
	if (!connectorPtr)
	{
		return false;
	}

	return reinterpret_cast<const Connector*>(connectorPtr)->GetQuoteReport(msg3, msg3Size, nonce, pseEnabled, outReport, outSign, outCert);
}

extern "C" int ocall_decent_ias_get_revoc_list(const void* const connector_ptr, const sgx_epid_group_id_t* gid, char** outRevcList, size_t* outSize)
{
	if (!connector_ptr || !gid ||
		!outRevcList || !outSize)
	{
		return false;
	}

	*outRevcList = nullptr;

	std::string revcList;
	if (!StatConnector::GetRevocationList(connector_ptr, *gid, revcList))
	{
		return false;
	}

	*outRevcList = new char[revcList.size()];
	*outSize = revcList.size();
	std::memcpy(*outRevcList, revcList.data(), revcList.size());
	return true;
}

extern "C" int ocall_decent_ias_get_quote_report(const void* const connector_ptr, const sgx_ra_msg3_t* msg3, const size_t msg3_size,
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
	if (!StatConnector::GetQuoteReport(connector_ptr, *msg3, msg3_size, nonce, pse_enabled == 1, report, sign, cert))
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
