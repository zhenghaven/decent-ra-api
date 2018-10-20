#include "IASConnector.h"

#include "IASUtil.h"

#include <sgx_key_exchange.h>

#include <json/json.h>

#include "../../../common/DataCoding.h"
#include "../../../common/SGX/IasConnector.h"

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
	return IASUtil::GetQuoteReport(iasReqRoot.toStyledString(), outReport, outSign, outCert, m_certPath, m_keyPath);
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
