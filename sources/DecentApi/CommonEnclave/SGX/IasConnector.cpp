#include "../../Common/SGX/IasConnector.h"

#include "edl_decent_tools.h"
#include "edl_decent_sgx_sp.h"

using namespace Decent::Ias;

bool StatConnector::GetRevocationList(const void* const connectorPtr, const sgx_epid_group_id_t& gid, std::string& outRevcList)
{
	if (!connectorPtr)
	{
		return false;
	}

	char* revcList = nullptr;
	size_t listSize = 0;
	int retVal = 0;
	if (ocall_decent_ias_get_revoc_list(&retVal, connectorPtr, &gid, &revcList, &listSize) != SGX_SUCCESS ||
		!retVal ||
		!revcList)
	{
		return false;
	}

	outRevcList.resize(listSize);
	std::copy(revcList, revcList + listSize, outRevcList.begin());

	ocall_decent_tools_del_buf_char(revcList);

	return true;
}

bool StatConnector::GetQuoteReport(const void* const connectorPtr, const sgx_ra_msg3_t& msg3, const size_t msg3Size,
	const std::string& nonce, const bool pseEnabled,
	std::string& outReport, std::string& outSign, std::string& outCert)
{
	if (!connectorPtr)
	{
		return false;
	}

	char* report = nullptr;
	char* sign = nullptr;
	char* cert = nullptr;
	size_t reportSize = 0;
	size_t signSize = 0;
	size_t certSize = 0;

	int retVal = 0;
	if (ocall_decent_ias_get_quote_report(&retVal, connectorPtr, &msg3, msg3Size, nonce.c_str(), pseEnabled,
		&report, &reportSize, &sign, &signSize, &cert, &certSize) != SGX_SUCCESS ||
		!retVal ||
		!report || !sign || !cert)
	{
		return false;
	}

	outReport.resize(reportSize);
	std::copy(report, report + reportSize, outReport.begin());

	ocall_decent_tools_del_buf_char(report);

	outSign.resize(signSize);
	std::copy(sign, sign + signSize, outSign.begin());

	ocall_decent_tools_del_buf_char(sign);

	outCert.resize(certSize);
	std::copy(cert, cert + certSize, outCert.begin());

	ocall_decent_tools_del_buf_char(cert);

	return true;
}