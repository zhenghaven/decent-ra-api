#include "EnclaveServiceProvider.h"

#include "edl_decent_sgx_sp.h"

#include "../../Common/SGX/SgxCryptoConversions.h"
#include "EnclaveRuntimeException.h"

using namespace Decent::Sgx;
using namespace Decent::Tools;

EnclaveServiceProvider::EnclaveServiceProvider(const std::shared_ptr<Decent::Ias::Connector>& ias, const std::string & enclavePath, const std::string & tokenPath) :
	Sgx::EnclaveBase(enclavePath, tokenPath),
	m_ias(ias)
{
}

EnclaveServiceProvider::EnclaveServiceProvider(const std::shared_ptr<Decent::Ias::Connector>& ias, const fs::path& enclavePath, const fs::path& tokenPath) :
	Sgx::EnclaveBase(enclavePath, tokenPath),
	m_ias(ias)
{
}

EnclaveServiceProvider::EnclaveServiceProvider(const std::shared_ptr<Decent::Ias::Connector>& ias, const std::string & enclavePath, const KnownFolderType tokenLocType, const std::string & tokenFileName) :
	Sgx::EnclaveBase(enclavePath, tokenLocType, tokenFileName),
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
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_enclave_get_pub_sign_key);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION_INT(retval, ecall_enclave_get_pub_sign_key);
}

bool EnclaveServiceProvider::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Decent::Net::Connection& connection)
{
	return EnclaveBase::ProcessSmartMessage(category, jsonMsg, connection);
}
