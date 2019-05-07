#include "DecentralizedEnclave.h"

#include "../../Common/SGX/RuntimeError.h"
#include "edl_decent_sgx_decentralized.h"

using namespace Decent::Ias;
using namespace Decent::Sgx;
using namespace Decent::Net;
using namespace Decent::Tools;

static void InitDecent(sgx_enclave_id_t id, const sgx_spid_t& spid)
{
	sgx_status_t retval = SGX_SUCCESS;
	DECENT_CHECK_SGX_STATUS_ERROR(ecall_decent_sgx_decentralized_init(id, &retval, &spid), ecall_decent_sgx_decentralized_init);
	DECENT_CHECK_SGX_STATUS_ERROR(retval, ecall_decent_sgx_decentralized_init);
}

DecentralizedEnclave::DecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<Connector>& iasConnector, const std::string & enclavePath, const std::string & tokenPath) :
	Sgx::EnclaveServiceProvider(iasConnector, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
}

DecentralizedEnclave::DecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<Connector>& iasConnector, const fs::path& enclavePath, const fs::path& tokenPath) :
	Sgx::EnclaveServiceProvider(iasConnector, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
}

DecentralizedEnclave::DecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<Connector>& iasConnector, const std::string & enclavePath, const std::string & tokenPath, 
	const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep) :
	Sgx::EnclaveServiceProvider(iasConnector, enclavePath, tokenPath, numTWorker, numUWorker, retryFallback, retrySleep)
{
	InitDecent(GetEnclaveId(), spid);
}

DecentralizedEnclave::DecentralizedEnclave(const sgx_spid_t & spid, const std::shared_ptr<Connector>& iasConnector, const fs::path & enclavePath, const fs::path & tokenPath, 
	const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep) :
	Sgx::EnclaveServiceProvider(iasConnector, enclavePath, tokenPath, numTWorker, numUWorker, retryFallback, retrySleep)
{
	InitDecent(GetEnclaveId(), spid);
}

DecentralizedEnclave::~DecentralizedEnclave()
{
}

bool DecentralizedEnclave::ProcessSmartMessage(const std::string & category, ConnectionBase& connection, ConnectionBase*& freeHeldCnt)
{
	return false;
}
