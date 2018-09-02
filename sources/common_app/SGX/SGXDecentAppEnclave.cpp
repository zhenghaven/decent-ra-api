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

bool SGXDecentAppEnclave::SendReportDataToServer(const std::string & decentId, const std::unique_ptr<Connection>& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_decent_app_send_report_data(GetEnclaveId(), &retval, decentId.c_str(), connection.get(), nullptr);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_process_ias_ra_report);

	return retval == SGX_SUCCESS;
}

bool SGXDecentAppEnclave::ProcessAppReportSignMsg(const std::string & trustedMsg)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	m_sgxEnclaveReport.reset(new sgx_report_body_t);
	m_sgxEnclaveReportSign.reset(new sgx_ec256_signature_t);

	enclaveRet = ecall_decent_app_proc_app_sign_msg(GetEnclaveId(), &retval, trustedMsg.c_str(), m_sgxEnclaveReport.get(), m_sgxEnclaveReportSign.get());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_proc_app_sign_msg);

	if (retval == SGX_SUCCESS)
	{
		m_enclaveReport = SerializeStruct(*m_sgxEnclaveReport);
		m_enclaveReportSign = SerializeStruct(*m_sgxEnclaveReportSign);
	}
	else
	{
		m_sgxEnclaveReport.reset();
		m_sgxEnclaveReportSign.reset();
	}

	return retval == SGX_SUCCESS;
}

const std::string & SGXDecentAppEnclave::GetDecentRAReport() const
{
	return m_decentRAReport;
}

const std::string & SGXDecentAppEnclave::GetEnclaveReport() const
{
	return m_enclaveReport;
}

const std::string & SGXDecentAppEnclave::GetEnclaveReportSign() const
{
	return m_enclaveReportSign;
}

bool SGXDecentAppEnclave::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, std::unique_ptr<Connection>& connection)
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
