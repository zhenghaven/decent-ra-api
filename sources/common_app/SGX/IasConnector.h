#pragma once

#include <cstdint>

#include <string>

typedef uint8_t sgx_epid_group_id_t[4];
typedef struct _ra_msg3_t sgx_ra_msg3_t;

class IASConnector
{
public:
#if !defined(NDEBUG) || defined(EDEBUG)
	static constexpr char const sk_iasUrl[] = "https://test-as.sgx.trustedservices.intel.com:443";
#else
	static constexpr char const sk_iasUrl[] = "https://as.sgx.trustedservices.intel.com:443";
#endif
	static constexpr char const sk_iasSigRlPath[] = "/attestation/sgx/v2/sigrl/";
	static constexpr char const sk_iasReportPath[] = "/attestation/sgx/v2/report";
	static const std::string sk_iasUrlStr;
	static const std::string sk_defaultCertPath;
	static const std::string sk_defaultKeyPath;
	static const std::string sk_defaultRsaKeyPath;

	static bool GetRevocationList(const sgx_epid_group_id_t& gid, const std::string& certPath, const std::string& keyPath, 
		std::string & outRevcList);

	static bool GetQuoteReport(const std::string& jsonReqBody, const std::string& certPath, const std::string& keyPath, 
		std::string& outReport, std::string& outSign, std::string& outCert);

public:
	IASConnector();
	IASConnector(const std::string& certPath, const std::string& keyPath);
	virtual ~IASConnector();

	virtual bool GetRevocationList(const sgx_epid_group_id_t& gid, std::string& outRevcList) const;

	virtual bool GetQuoteReport(const sgx_ra_msg3_t& msg3, const size_t msg3Size, const std::string& nonce, const bool pseEnabled, std::string& outReport, std::string& outSign, std::string& outCert) const;

private:
	const std::string m_certPath;
	const std::string m_keyPath;
};
