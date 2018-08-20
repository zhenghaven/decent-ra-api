#pragma once

#include <string>

#include <sgx_quote.h>

class IASConnector
{
public:
	IASConnector();
	IASConnector(const std::string& certPath, const std::string& keyPath);
	virtual ~IASConnector();

	virtual int16_t GetRevocationList(const sgx_epid_group_id_t& gid, std::string& outRevcList) const;

	virtual int16_t GetQuoteReport(const std::string& jsonReqBody, std::string& outReport, std::string& outSign, std::string& outCert) const;

private:
	const std::string m_certPath;
	const std::string m_keyPath;
};
