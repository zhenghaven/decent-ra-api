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

int16_t IASConnector::GetRevocationList(const sgx_epid_group_id_t & gid, std::string & outRevcList)
{
	return IASUtil::GetRevocationList(gid, outRevcList, m_certPath, m_keyPath);
}

int16_t IASConnector::GetQuoteReport(const std::string & jsonReqBody, std::string & outReport, std::string & outSign, std::string & outCert)
{
	return IASUtil::GetQuoteReport(jsonReqBody, outReport, outSign, outCert, m_certPath, m_keyPath);
}
