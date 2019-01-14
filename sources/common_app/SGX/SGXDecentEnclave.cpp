#include "../../common/ModuleConfigInternal.h"

#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "SGXDecentEnclave.h"

#include <thread>
#include <cstring>

#include <sgx_ukey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_uae_service.h>

#include <Enclave_u.h>

#include "../common/DataCoding.h"

#include "../DecentMessages/DecentMessage.h"
#include "../DecentMessages/DecentAppMessage.h"
#include "../DecentAppLASession.h"
#include "../DecentRASession.h"

#include "SGXEnclaveRuntimeException.h"

static void InitDecent(sgx_enclave_id_t id, const sgx_spid_t& spid)
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decent_init(id, &retval, &spid);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_init);
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const std::string& tokenPath) :
	SGXEnclaveServiceProvider(ias, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
	m_selfRaReport = GenerateDecentSelfRAReport();
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const fs::path& enclavePath, const fs::path& tokenPath) :
	SGXEnclaveServiceProvider(ias, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
	m_selfRaReport = GenerateDecentSelfRAReport();
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName) :
	SGXEnclaveServiceProvider(ias, enclavePath, tokenLocType, tokenFileName)
{
	InitDecent(GetEnclaveId(), spid);
	m_selfRaReport = GenerateDecentSelfRAReport();
}

SGXDecentEnclave::~SGXDecentEnclave()
{
	ecall_decent_terminate(GetEnclaveId());
}

std::string SGXDecentEnclave::GetDecentSelfRAReport() const
{
	return m_selfRaReport;
}
//
//bool SGXDecentEnclave::ProcessDecentSelfRAReport(const std::string & inReport)
//{
//	sgx_status_t enclaveRet = SGX_SUCCESS;
//	int retval = SGX_SUCCESS;
//
//	enclaveRet = ecall_decent_process_ias_ra_report(GetEnclaveId(), &retval, inReport.c_str());
//	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_process_ias_ra_report);
//
//	return retval != 0;
//}

bool SGXDecentEnclave::ProcessAppX509Req(Connection& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_proc_app_x509_req(GetEnclaveId(), &retval, &connection);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_proc_app_x509_req);

	return retval == SGX_SUCCESS;
}

bool SGXDecentEnclave::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	if (category == DecentAppMessage::sk_ValueCat)
	{
		return DecentServerLASession::SmartMsgEntryPoint(connection, *this, *this, jsonMsg);
	}
	else
	{
		return false;
	}
}

std::string SGXDecentEnclave::GenerateDecentSelfRAReport()
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decent_server_generate_x509(GetEnclaveId(), &retval, m_ias.get(), GetEnclaveId());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_generate_x509);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_server_generate_x509);

	size_t certLen = 0;

	enclaveRet = ecall_decent_server_get_x509_pem(GetEnclaveId(), &certLen, nullptr, 0);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_get_x509_pem);

	std::string retReport(certLen, '\0');
	
	enclaveRet = ecall_decent_server_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_get_x509_pem);

	return retReport;
}

extern "C" int ocall_decent_ra_get_msg1(const uint64_t enclave_id, const uint32_t ra_ctx, sgx_ra_msg1_t* msg1)
{
	if (!msg1)
	{
		return false;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::thread tmpThread([&enclaveRet, enclave_id, ra_ctx, msg1]() {
		enclaveRet = sgx_ra_get_msg1(ra_ctx, enclave_id, decent_ra_get_ga, msg1);
	});
	tmpThread.join();

	return (enclaveRet == SGX_SUCCESS);
}

extern "C" size_t ocall_decent_ra_proc_msg2(const uint64_t enclave_id, const uint32_t ra_ctx, const sgx_ra_msg2_t* msg2, const size_t msg2_size, uint8_t** out_msg3)
{
	if (!msg2 || !out_msg3)
	{
		return 0;
	}

	*out_msg3 = nullptr;

	sgx_ra_msg3_t* tmpMsg3 = nullptr;
	uint32_t tmpMsg3Size = 0;
	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::thread tmpThread([&enclaveRet, enclave_id, ra_ctx, msg2, msg2_size, &tmpMsg3, &tmpMsg3Size]() {
		enclaveRet = sgx_ra_proc_msg2(ra_ctx, enclave_id, decent_ra_proc_msg2_trusted, decent_ra_get_msg3_trusted,
			msg2, static_cast<uint32_t>(msg2_size), &tmpMsg3, &tmpMsg3Size);
	});
	tmpThread.join();

	if (enclaveRet != SGX_SUCCESS)
	{
		return 0;
	}

	//Copy msg3 to our buffer pointer to avoid the mix use of malloc and delete[];
	*out_msg3 = new uint8_t[tmpMsg3Size];
	std::memcpy(*out_msg3, tmpMsg3, tmpMsg3Size);
	std::free(tmpMsg3);

	return tmpMsg3Size;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
