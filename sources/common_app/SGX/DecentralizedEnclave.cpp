#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL

#include "DecentralizedEnclave.h"

#include "EnclaveRuntimeException.h"

#include <Enclave_u.h>

using namespace Decent::Sgx;

static void InitDecent(sgx_enclave_id_t id, const sgx_spid_t& spid)
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decentralized_init(id, &retval, &spid);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_init);
}

DecentralizedEnclave::DecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<Decent::Ias::Connector>& iasConnector, const std::string & enclavePath, const std::string & tokenPath) :
	Sgx::EnclaveServiceProvider(iasConnector, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
}

DecentralizedEnclave::DecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<Decent::Ias::Connector>& iasConnector, const fs::path& enclavePath, const fs::path& tokenPath) :
	Sgx::EnclaveServiceProvider(iasConnector, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
}

DecentralizedEnclave::DecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<Decent::Ias::Connector>& iasConnector, const std::string & enclavePath, const KnownFolderType tokenLocType, const std::string & tokenFileName) :
	Sgx::EnclaveServiceProvider(iasConnector, enclavePath, tokenLocType, tokenFileName)
{
	InitDecent(GetEnclaveId(), spid);
}

DecentralizedEnclave::~DecentralizedEnclave()
{
}

bool DecentralizedEnclave::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Decent::Net::Connection& connection)
{
	return false;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
