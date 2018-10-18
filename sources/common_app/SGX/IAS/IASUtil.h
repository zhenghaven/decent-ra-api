#pragma once

#include <string>

#include <sgx_quote.h>

namespace IASUtil
{
	bool GetRevocationList(const sgx_epid_group_id_t& gid, std::string & outRevcList, const std::string& certPath, const std::string& keyPath);

	bool GetQuoteReport(const std::string& jsonReqBody, std::string& outReport, std::string& outSign, std::string& outCert, const std::string& certPath, const std::string& keyPath);

	inline std::string GetIasUrlHost()
	{
#if !defined(NDEBUG) || defined(EDEBUG)
		return "https://test-as.sgx.trustedservices.intel.com:443";
#else
		return "https://as.sgx.trustedservices.intel.com:443";
#endif
	}

	inline std::string GetIasUrlSigRlPath()
	{
		return "/attestation/sgx/v2/sigrl/";
	}

	inline std::string GetIasUrlReportPath()
	{
		return "/attestation/sgx/v2/report";
	}

	std::string GetDefaultIasDirPath();

	std::string GetDefaultCertPath();

	std::string GetDefaultKeyPath();

	std::string GetDefaultRsaKeyPath();
}
