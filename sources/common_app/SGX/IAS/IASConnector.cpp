#include "IASConnector.h"

#include "IASUtil.h"

IASConnector::IASConnector() :
	IASConnector(IASUtil::GetDefaultCertPath(), IASUtil::GetDefaultKeyPath())
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
	return IASUtil::GetRevocationList(gid, outRevcList, m_certPath, m_keyPath);
}

bool IASConnector::GetQuoteReport(const std::string & jsonReqBody, std::string & outReport, std::string & outSign, std::string & outCert) const
{
	return IASUtil::GetQuoteReport(jsonReqBody, outReport, outSign, outCert, m_certPath, m_keyPath);
}
