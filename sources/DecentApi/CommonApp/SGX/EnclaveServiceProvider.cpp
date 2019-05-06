#include "EnclaveServiceProvider.h"

#include "edl_decent_sgx_sp.h"

#include "../../Common/SGX/SgxCryptoConversions.h"
#include "../../Common/SGX/RuntimeError.h"
#include "../Base/EnclaveException.h"

using namespace Decent::Ias;
using namespace Decent::Sgx;
using namespace Decent::Tools;

EnclaveServiceProvider::EnclaveServiceProvider(const std::shared_ptr<Connector>& ias, const std::string & enclavePath, const std::string & tokenPath) :
	Sgx::EnclaveBase(enclavePath, tokenPath),
	m_ias(ias)
{
}

EnclaveServiceProvider::EnclaveServiceProvider(const std::shared_ptr<Connector>& ias, const fs::path& enclavePath, const fs::path& tokenPath) :
	Sgx::EnclaveBase(enclavePath, tokenPath),
	m_ias(ias)
{
}

EnclaveServiceProvider::EnclaveServiceProvider(const std::shared_ptr<Connector>& ias, const std::string & enclavePath, const std::string & tokenPath, 
	const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep) :
	Sgx::EnclaveBase(enclavePath, tokenPath, numTWorker, numUWorker, retryFallback, retrySleep),
	m_ias(ias)
{
}

EnclaveServiceProvider::EnclaveServiceProvider(const std::shared_ptr<Connector>& ias, const fs::path & enclavePath, const fs::path & tokenPath, 
	const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep) :
	Sgx::EnclaveBase(enclavePath, tokenPath, numTWorker, numUWorker, retryFallback, retrySleep),
	m_ias(ias)
{
}

EnclaveServiceProvider::~EnclaveServiceProvider()
{
}

const char * EnclaveServiceProvider::GetPlatformType() const
{
	return EnclaveBase::GetPlatformType();
}

void EnclaveServiceProvider::GetSpPublicSignKey(general_secp256r1_public_t & outKey) const
{
	int retval = 0;

	sgx_status_t enclaveRet = ecall_decent_sgx_sp_get_pub_sign_key(GetEnclaveId(), &retval, GeneralEc256Type2Sgx(&outKey));
	DECENT_CHECK_SGX_STATUS_ERROR(enclaveRet, ecall_decent_sgx_sp_get_pub_sign_key);
	DECENT_ASSERT_ENCLAVE_APP_RESULT(retval, "get service provider public key");
}

bool EnclaveServiceProvider::ProcessSmartMessage(const std::string & category, Decent::Net::ConnectionBase& connection)
{
	return EnclaveBase::ProcessSmartMessage(category, connection);
}
