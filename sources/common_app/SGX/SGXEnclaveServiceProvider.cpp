#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENTRALIZED_ENCLAVE_INTERNAL || USE_DECENT_ENCLAVE_SERVER_INTERNAL)

#include "SGXEnclaveServiceProvider.h"

#include <Enclave_u.h>

#include "../../common/SGX/SgxCryptoConversions.h"
#include "SGXEnclaveRuntimeException.h"

SGXEnclaveServiceProvider::SGXEnclaveServiceProvider(const std::shared_ptr<IASConnector>& ias, const std::string & enclavePath, const std::string & tokenPath) :
	SGXEnclave(enclavePath, tokenPath),
	m_ias(ias)
{
}

SGXEnclaveServiceProvider::SGXEnclaveServiceProvider(const std::shared_ptr<IASConnector>& ias, const fs::path& enclavePath, const fs::path& tokenPath) :
	SGXEnclave(enclavePath, tokenPath),
	m_ias(ias)
{
}

SGXEnclaveServiceProvider::SGXEnclaveServiceProvider(const std::shared_ptr<IASConnector>& ias, const std::string & enclavePath, const KnownFolderType tokenLocType, const std::string & tokenFileName) :
	SGXEnclave(enclavePath, tokenLocType, tokenFileName),
	m_ias(ias)
{
}

SGXEnclaveServiceProvider::~SGXEnclaveServiceProvider()
{
}

const char * SGXEnclaveServiceProvider::GetPlatformType() const
{
	return SGXEnclave::GetPlatformType();
}

void SGXEnclaveServiceProvider::GetSpPublicSignKey(general_secp256r1_public_t & outKey) const
{
	int retval = 0;

	sgx_status_t enclaveRet = ecall_enclave_get_pub_sign_key(GetEnclaveId(), &retval, GeneralEc256Type2Sgx(&outKey));
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_enclave_get_pub_sign_key);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION_INT(retval, ecall_enclave_get_pub_sign_key);
}

bool SGXEnclaveServiceProvider::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	return SGXEnclave::ProcessSmartMessage(category, jsonMsg, connection);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && (USE_DECENTRALIZED_ENCLAVE_INTERNAL || USE_DECENT_ENCLAVE_SERVER_INTERNAL)
