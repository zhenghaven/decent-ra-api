#include "../../Common/Ra/KeyContainer.h"

#include <memory>
#include <exception>

#include <sgx_tcrypto.h>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/SGX/SgxCryptoConversions.h"

using namespace Decent;
using namespace Decent::Ra;

namespace
{
	static std::pair<std::unique_ptr<general_secp256r1_public_t>, std::unique_ptr<PrivateKeyWrap> > ConstructKeyPair()
	{
		std::unique_ptr<general_secp256r1_public_t> pub = Tools::make_unique<general_secp256r1_public_t>();
		std::unique_ptr<PrivateKeyWrap> prv = Tools::make_unique<PrivateKeyWrap>();

		sgx_ecc_state_handle_t eccState = nullptr;
		if (!pub || !prv ||
			sgx_ecc256_open_context(&eccState) != SGX_SUCCESS ||
			sgx_ecc256_create_key_pair(GeneralEc256Type2Sgx(&prv->m_prvKey), GeneralEc256Type2Sgx(pub.get()), eccState) != SGX_SUCCESS)
		{
			sgx_ecc256_close_context(eccState);
			LOGW("Failed to create new key pair!");
			throw std::runtime_error("Failed to create new key pair!"); //If error happened, this should be thrown at the program startup.
		}
		sgx_ecc256_close_context(eccState);

		return std::make_pair(std::move(pub), std::move(prv));
	}
}

KeyContainer::KeyContainer() :
	KeyContainer(std::move(ConstructKeyPair()))
{
}
