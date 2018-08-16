#include "SGXEnclaveServiceProvider.h"

#include <Enclave_u.h>

#include "../../common/SGX/sgx_constants.h"

#include "SGXEnclaveRuntimeException.h"

SGXEnclaveServiceProvider::SGXEnclaveServiceProvider(const std::string & enclavePath, const std::string & tokenPath, IASConnector ias) :
	SGXEnclave(enclavePath, tokenPath),
	SGXServiceProvider(ias)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_sgx_ra_sp_init(GetEnclaveId(), &retval);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_init_ra_sp_environment);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_init_ra_sp_environment);
}

SGXEnclaveServiceProvider::SGXEnclaveServiceProvider(const std::string & enclavePath, const fs::path tokenPath, IASConnector ias) :
	SGXEnclave(enclavePath, tokenPath),
	SGXServiceProvider(ias)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_sgx_ra_sp_init(GetEnclaveId(), &retval);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_init_ra_sp_environment);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_init_ra_sp_environment);
}

SGXEnclaveServiceProvider::SGXEnclaveServiceProvider(const std::string & enclavePath, const KnownFolderType tokenLocType, const std::string & tokenFileName, IASConnector ias) :
	SGXEnclave(enclavePath, tokenLocType, tokenFileName),
	SGXServiceProvider(ias)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_sgx_ra_sp_init(GetEnclaveId(), &retval);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_init_ra_sp_environment);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_init_ra_sp_environment);
}

SGXEnclaveServiceProvider::~SGXEnclaveServiceProvider()
{
	ecall_sgx_ra_sp_terminate(GetEnclaveId());
}

void SGXEnclaveServiceProvider::GetRASPSignPubKey(sgx_ec256_public_t & outKey)
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

sgx_status_t SGXEnclaveServiceProvider::ProcessRAMsg3(const std::string & clientID, const sgx_ra_msg3_t & inMsg3, const uint32_t msg3Len, const std::string & iasReport, const std::string & reportSign, const std::string & reportCertChain, sgx_ra_msg4_t & outMsg4, sgx_ec256_signature_t & outMsg4Sign)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_process_ra_msg3(GetEnclaveId(), &retval, clientID.c_str(), reinterpret_cast<const uint8_t*>(&inMsg3), msg3Len, iasReport.c_str(), reportSign.c_str(), reportCertChain.c_str(), &outMsg4, &outMsg4Sign);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg3);

	return retval;
}
