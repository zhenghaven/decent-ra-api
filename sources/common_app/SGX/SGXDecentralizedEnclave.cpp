#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL

#include "SGXDecentralizedEnclave.h"

#include "SGXEnclaveRuntimeException.h"

#include <Enclave_u.h>

static void InitDecent(sgx_enclave_id_t id, const sgx_spid_t& spid)
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decentralized_init(id, &retval, &spid);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_init);
}

SGXDecentralizedEnclave::SGXDecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<IASConnector>& iasConnector, const std::string & enclavePath, const std::string & tokenPath) :
	SGXEnclaveServiceProvider(iasConnector, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
}

SGXDecentralizedEnclave::SGXDecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<IASConnector>& iasConnector, const fs::path& enclavePath, const fs::path& tokenPath) :
	SGXEnclaveServiceProvider(iasConnector, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
}

SGXDecentralizedEnclave::SGXDecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<IASConnector>& iasConnector, const std::string & enclavePath, const KnownFolderType tokenLocType, const std::string & tokenFileName) :
	SGXEnclaveServiceProvider(iasConnector, enclavePath, tokenLocType, tokenFileName)
{
	InitDecent(GetEnclaveId(), spid);
}

SGXDecentralizedEnclave::~SGXDecentralizedEnclave()
{
}

bool SGXDecentralizedEnclave::ToDecentralizedNode(const std::string & id, bool isSP)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_to_decentralized_node(GetEnclaveId(), &retval, id.c_str(), isSP);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_transit_to_decent_node);

	return retval == SGX_SUCCESS;
}

bool SGXDecentralizedEnclave::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	return false;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
