#pragma once

#include <cstdint>

#include <string>

typedef uint8_t sgx_epid_group_id_t[4];
typedef struct _ra_msg3_t sgx_ra_msg3_t;

class IASConnector
{
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
