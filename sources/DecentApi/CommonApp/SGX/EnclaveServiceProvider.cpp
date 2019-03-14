#include "EnclaveServiceProvider.h"

#include "edl_decent_sgx_sp.h"

#include "../../Common/SGX/SgxCryptoConversions.h"
#include "../../Common/SGX/RuntimeError.h"
#include "../Base/EnclaveException.h"

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
	DECENT_CHECK_SGX_STATUS_ERROR(enclaveRet, ecall_decent_sgx_sp_get_pub_sign_key);
	DECENT_ASSERT_ENCLAVE_APP_RESULT(retval, "get service provider public key");
}

bool EnclaveServiceProvider::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Decent::Net::Connection& connection)
{
	return EnclaveBase::ProcessSmartMessage(category, jsonMsg, connection);
}
