#include "../../common/ModuleConfigInternal.h"

#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "DecentServer.h"

#include <thread>
#include <cstring>

#include <sgx_ukey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_uae_service.h>

#include <Enclave_u.h>

#include "../../common/Tools/DataCoding.h"

#include "../Ra/Messages.h"
#include "../SGX/EnclaveRuntimeException.h"

using namespace Decent::DecentSgx;
using namespace Decent::Net;
using namespace Decent::Ias;

namespace
{
	static void InitDecent(sgx_enclave_id_t id, const sgx_spid_t& spid)
	{
		sgx_status_t retval = SGX_SUCCESS;
		sgx_status_t enclaveRet = ecall_decent_init(id, &retval, &spid);
		CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_init);
		CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_init);
	}
}

DecentServer::DecentServer(const sgx_spid_t& spid, const std::shared_ptr<Connector>& ias, const std::string& enclavePath, const std::string& tokenPath) :
	Sgx::EnclaveServiceProvider(ias, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
	m_selfRaReport = GenerateDecentSelfRAReport();
}

DecentServer::DecentServer(const sgx_spid_t& spid, const std::shared_ptr<Connector>& ias, const fs::path& enclavePath, const fs::path& tokenPath) :
	Sgx::EnclaveServiceProvider(ias, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
	m_selfRaReport = GenerateDecentSelfRAReport();
}

DecentServer::DecentServer(const sgx_spid_t& spid, const std::shared_ptr<Connector>& ias, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName) :
	Sgx::EnclaveServiceProvider(ias, enclavePath, tokenLocType, tokenFileName)
{
	InitDecent(GetEnclaveId(), spid);
	m_selfRaReport = GenerateDecentSelfRAReport();
}

DecentServer::~DecentServer()
{
	ecall_decent_terminate(GetEnclaveId());
}

std::string DecentServer::GetDecentSelfRAReport() const
{
	return m_selfRaReport;
}

void DecentServer::LoadConstWhiteList(const std::string & key, const std::string & whiteList)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	int retval = 0;

	enclaveRet = ecall_decent_server_load_const_white_list(GetEnclaveId(), &retval, key.c_str(), whiteList.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_load_const_white_list);
}

void DecentServer::ProcessAppCertReq(const std::string & wListKey, Connection& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_server_proc_app_cert_req(GetEnclaveId(), &retval, wListKey.c_str(), &connection);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_proc_app_cert_req);
}

bool DecentServer::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	using namespace Decent::Ra::Message;

	if (category == LoadWhiteList::sk_ValueCat)
	{
		LoadWhiteList wlistMsg(jsonMsg);
		LoadConstWhiteList(wlistMsg.GetKey(), wlistMsg.GetWhiteList());
		return false;
	}
	else if (category == RequestAppCert::sk_ValueCat)
	{
		RequestAppCert certReqMsg(jsonMsg);
		ProcessAppCertReq(certReqMsg.GetKey(), connection);
		return false;
	}
	else
	{
		return false;
	}
}

std::string DecentServer::GenerateDecentSelfRAReport()
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
