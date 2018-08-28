#include "../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL

#include "SGXEnclaveServiceProvider.h"

#include <Enclave_u.h>

#include "../../common/SGX/sgx_constants.h"

#include "SGXRAMessages/SGXRAMessage.h"
#include "SGXEnclaveRuntimeException.h"
#include "SGXServiceProviderRASession.h"

static inline void InitSGXRASP(const sgx_enclave_id_t& eid)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_sgx_ra_sp_init(eid, &retval);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_init_ra_sp_environment);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_init_ra_sp_environment);
}

SGXEnclaveServiceProvider::SGXEnclaveServiceProvider(const std::string & enclavePath, const std::string & tokenPath, IASConnector ias) :
	SGXEnclave(enclavePath, tokenPath),
	m_ias(ias)
{
	InitSGXRASP(GetEnclaveId());
}

SGXEnclaveServiceProvider::SGXEnclaveServiceProvider(const std::string & enclavePath, const fs::path tokenPath, IASConnector ias) :
	SGXEnclave(enclavePath, tokenPath),
	m_ias(ias)
{
	InitSGXRASP(GetEnclaveId());
}

SGXEnclaveServiceProvider::SGXEnclaveServiceProvider(const std::string & enclavePath, const KnownFolderType tokenLocType, const std::string & tokenFileName, IASConnector ias) :
	SGXEnclave(enclavePath, tokenLocType, tokenFileName),
	m_ias(ias)
{
	InitSGXRASP(GetEnclaveId());
}

SGXEnclaveServiceProvider::~SGXEnclaveServiceProvider()
{
	ecall_sgx_ra_sp_terminate(GetEnclaveId());
}

std::shared_ptr<ServiceProviderRASession> SGXEnclaveServiceProvider::GetRASPSession(std::unique_ptr<Connection>& connection)
{
	return std::make_shared<SGXServiceProviderRASession>(connection, *this, m_ias);
}

void SGXEnclaveServiceProvider::GetRAClientSignPubKey(sgx_ec256_public_t & outKey) const
{
	SGXEnclave::GetRAClientSignPubKey(outKey);
}

std::shared_ptr<ClientRASession> SGXEnclaveServiceProvider::GetRAClientSession(std::unique_ptr<Connection>& connection)
{
	return SGXEnclave::GetRAClientSession(connection);
}

void SGXEnclaveServiceProvider::GetRASPSignPubKey(sgx_ec256_public_t & outKey) const
{
	sgx_status_t retval = SGX_SUCCESS;

	sgx_status_t enclaveRet = ecall_get_ra_sp_pub_sig_key(GetEnclaveId(), &retval, &outKey);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_get_ra_sp_pub_sig_key);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_init_ra_sp_environment);
}

sgx_status_t SGXEnclaveServiceProvider::GetIasReportNonce(const std::string & clientID, std::string & outNonce)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	outNonce.resize(IAS_REQUEST_NONCE_SIZE);
	enclaveRet = ecall_get_ias_nonce(GetEnclaveId(), &retval, clientID.c_str(), &outNonce[0]);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_get_ias_nonce);

	return retval;
}

sgx_status_t SGXEnclaveServiceProvider::ProcessRAMsg0Send(const std::string & clientID)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_process_ra_msg0_send(GetEnclaveId(), &retval, clientID.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg0_send);

	return retval;
}

sgx_status_t SGXEnclaveServiceProvider::ProcessRAMsg1(const std::string & clientID, const sgx_ra_msg1_t & inMsg1, sgx_ra_msg2_t & outMsg2)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_process_ra_msg1(GetEnclaveId(), &retval, clientID.c_str(), &inMsg1, &outMsg2);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg1);

	return retval;
}

sgx_status_t SGXEnclaveServiceProvider::ProcessRAMsg3(const std::string & clientID, const std::vector<uint8_t> & inMsg3, const std::string & iasReport, const std::string & reportSign, const std::string & reportCertChain, sgx_ra_msg4_t & outMsg4, sgx_ec256_signature_t & outMsg4Sign, sgx_report_data_t* outOriRD)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_process_ra_msg3(GetEnclaveId(), &retval, clientID.c_str(), inMsg3.data(), static_cast<uint32_t>(inMsg3.size()), iasReport.c_str(), reportSign.c_str(), reportCertChain.c_str(), &outMsg4, &outMsg4Sign, outOriRD);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg3);

	return retval;
}

bool SGXEnclaveServiceProvider::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, std::unique_ptr<Connection>& connection)
{
	if (category == SGXRASPMessage::sk_ValueCat)
	{
		return SGXServiceProviderRASession::SmartMsgEntryPoint(connection, *this, m_ias, jsonMsg);
	}
	else
	{
		return SGXEnclave::ProcessSmartMessage(category, jsonMsg, connection);
	}
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL
