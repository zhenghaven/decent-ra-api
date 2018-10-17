#include "../../common/CryptoKeyContainer.h"

#include <memory>

#include <sgx_tcrypto.h>

#include "../../common/SGX/SGXCryptoConversions.h"

static std::pair<general_secp256r1_public_t*, PrivateKeyWrap*> ConstructKeyPair()
{
	std::pair<general_secp256r1_public_t*, PrivateKeyWrap*> res(std::make_pair(nullptr, nullptr));

	std::unique_ptr<general_secp256r1_public_t> pub(new general_secp256r1_public_t);
	std::unique_ptr<PrivateKeyWrap> prv(new PrivateKeyWrap);

	if (!pub || !prv)
	{
		return res;
	}

	sgx_ecc_state_handle_t eccState;
	sgx_status_t enclaveRet = sgx_ecc256_open_context(&eccState);
	if (enclaveRet != SGX_SUCCESS)
	{
		return res;
	}
	enclaveRet = sgx_ecc256_create_key_pair(GeneralEc256Type2Sgx(&prv->m_prvKey), GeneralEc256Type2Sgx(pub.get()), eccState);
	sgx_ecc256_close_context(eccState);
	if (enclaveRet != SGX_SUCCESS)
	{
		return res;
	}

	res.first = pub.release();
	res.second = prv.release();

	return res;
}

CryptoKeyContainer::CryptoKeyContainer() :
	CryptoKeyContainer(ConstructKeyPair())
{

}
