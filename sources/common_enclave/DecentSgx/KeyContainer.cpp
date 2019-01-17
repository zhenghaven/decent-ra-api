#include "../../common/Decent/KeyContainer.h"

#include <memory>

#include <sgx_tcrypto.h>

#include "../../common/CommonTool.h"
#include "../../common/SGX/SGXCryptoConversions.h"

namespace
{
	static std::pair<std::unique_ptr<general_secp256r1_public_t>, std::unique_ptr<PrivateKeyWrap> > ConstructKeyPair()
	{
		std::pair<std::unique_ptr<general_secp256r1_public_t>, std::unique_ptr<PrivateKeyWrap> > res =
			std::make_pair(Common::make_unique<general_secp256r1_public_t>(), Common::make_unique<PrivateKeyWrap>());

		sgx_ecc_state_handle_t eccState = nullptr;
		if (!res.first || !res.second ||
			sgx_ecc256_open_context(&eccState) != SGX_SUCCESS ||
			sgx_ecc256_create_key_pair(GeneralEc256Type2Sgx(&res.second->m_prvKey), GeneralEc256Type2Sgx(res.first.get()), eccState) != SGX_SUCCESS)
		{
			sgx_ecc256_close_context(eccState);
			throw std::exception("Failed to create new key pair!"); //This should be thrown at the program startup.
		}
		sgx_ecc256_close_context(eccState);

		return std::move(res);
	}
}


Decent::KeyContainer::KeyContainer() :
	KeyContainer(ConstructKeyPair())
{
}
