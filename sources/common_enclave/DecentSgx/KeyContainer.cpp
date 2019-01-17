#include "../../common/Decent/KeyContainer.h"

#include <memory>

#include <sgx_tcrypto.h>

#include "../../common/CommonTool.h"
#include "../../common/SGX/SgxCryptoConversions.h"

namespace
{
	static std::pair<std::unique_ptr<general_secp256r1_public_t>, std::unique_ptr<PrivateKeyWrap> > ConstructKeyPair()
	{
		std::unique_ptr<general_secp256r1_public_t> pub = Common::make_unique<general_secp256r1_public_t>();
		std::unique_ptr<PrivateKeyWrap> prv = Common::make_unique<PrivateKeyWrap>();

		sgx_ecc_state_handle_t eccState = nullptr;
		if (!pub || !prv ||
			sgx_ecc256_open_context(&eccState) != SGX_SUCCESS ||
			sgx_ecc256_create_key_pair(GeneralEc256Type2Sgx(&prv->m_prvKey), GeneralEc256Type2Sgx(pub.get()), eccState) != SGX_SUCCESS)
		{
			sgx_ecc256_close_context(eccState);
			LOGW("Failed to create new key pair!");
			throw std::exception("Failed to create new key pair!"); //This should be thrown at the program startup.
		}
		sgx_ecc256_close_context(eccState);

		return std::make_pair(std::move(pub), std::move(prv));
	}
}


Decent::KeyContainer::KeyContainer() :
	KeyContainer(std::move(ConstructKeyPair()))
{
}
