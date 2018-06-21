#pragma once

#include <string>
#include <functional>

#include <sgx_quote.h>

typedef std::function<size_t(char*, size_t, size_t, void*)> cUrlContentCallBackFunc;
typedef std::function<size_t(char*, size_t, size_t, void*)> cUrlHeaderCallBackFunc;

bool GetRevocationList(const sgx_epid_group_id_t& gid, std::string & outRevcList, const std::string& certPath, const std::string& keyPath);

bool GetRevocationList(const sgx_epid_group_id_t& gid, std::string& outRevcList);

inline std::string GetIasUrlHostDev()
{
	return "https://test-as.sgx.trustedservices.intel.com:443";
}

inline std::string GetIasUrlHostRelease()
{
	return "https://as.sgx.trustedservices.intel.com:443";
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
