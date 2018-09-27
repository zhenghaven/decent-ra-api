#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#include "SGXDecentAppEnclave.h"

#include <sgx_tcrypto.h>
#include <sgx_report.h>

#include "SGXEnclaveRuntimeException.h"

#include "../../common/DataCoding.h"
#include "../DecentAppLASession.h"
#include "SGXMessages/SGXLAMessage.h"

#include <Enclave_u.h>

SGXDecentAppEnclave::~SGXDecentAppEnclave()
{
}

bool SGXDecentAppEnclave::ProcessDecentSelfRAReport(std::string & inReport)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_decent_app_process_ias_ra_report(GetEnclaveId(), &retval, inReport.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_process_ias_ra_report);

	if (retval == SGX_SUCCESS)
	{
		m_decentRAReport.swap(inReport);
	}

	return retval == SGX_SUCCESS;
}

bool SGXDecentAppEnclave::SendCertReqToServer(const std::string & decentId, Connection& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_decent_app_send_x509_req(GetEnclaveId(), &retval, decentId.c_str(), &connection, nullptr);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_send_x509_req);

	return retval == SGX_SUCCESS;
}

bool SGXDecentAppEnclave::ProcessAppReportSignMsg(const std::string & trustedMsg)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_app_proc_app_x509_msg(GetEnclaveId(), &retval, trustedMsg.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_proc_app_x509_msg);

	if (retval != SGX_SUCCESS)
	{
		return false;
	}


	size_t certLen = 0;
	std::string retReport(5000, '\0');

	enclaveRet = ecall_decent_app_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_get_x509_pem);

	if (certLen > retReport.size())
	{
		retReport.resize(certLen);

		enclaveRet = ecall_decent_app_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
		CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_get_x509_pem);
	}

	retReport.resize(certLen);

	return retval == SGX_SUCCESS;
}

const std::string & SGXDecentAppEnclave::GetDecentRAReport() const
{
	return m_decentRAReport;
}

const std::string & SGXDecentAppEnclave::GetAppCert() const
{
	return m_appCert;
}

bool SGXDecentAppEnclave::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	if (category == SGXLAMessage::sk_ValueCat)
	{
		return DecentAppLASession::SmartMsgEntryPoint(connection, *this, *this, jsonMsg);
	}
	else
	{
		return false;
	}
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
