#include "../../Common/Ra/KeyContainer.h"

#include <memory>

#include <sgx_tcrypto.h>

#include <mbedTLScpp/EcKey.hpp>
#include <mbedTLScpp/SecretStruct.hpp>

#include "../../Common/Exceptions.h"
#include "../../Common/SGX/ErrorCode.h"

namespace
{
	static std::unique_ptr<mbedTLScpp::EcKeyPair<mbedTLScpp::EcType::SECP256R1> > ConstructNewKey()
	{
		using namespace mbedTLScpp;

		sgx_ec256_public_t pub;
		SecretStruct<sgx_ec256_private_t> prv;
		sgx_ecc_state_handle_t eccState = nullptr;

		auto retVal = sgx_ecc256_open_context(&eccState);
		if (retVal != SGX_SUCCESS)
		{
			throw Decent::RuntimeException(Decent::Sgx::ConstructSimpleErrorMsg(retVal, "sgx_ecc256_open_context"));
		}

		try
		{
			retVal = sgx_ecc256_create_key_pair(&prv.m_data, &pub, eccState);
			if (retVal != SGX_SUCCESS)
			{
				throw Decent::RuntimeException(Decent::Sgx::ConstructSimpleErrorMsg(retVal, "sgx_ecc256_create_key_pair"));
			}
		}
		catch (...)
		{
			sgx_ecc256_close_context(eccState);
			throw;
		}
		sgx_ecc256_close_context(eccState);

		return Internal::make_unique<EcKeyPair<EcType::SECP256R1> >(
			EcKeyPair<EcType::SECP256R1>::FromBytes(
				CtnFullR(SecretArray<uint8_t, 32>(prv.m_data.r)),
				CtnFullR(pub.gx),
				CtnFullR(pub.gy)
			)
		);
	}
}

Decent::Ra::KeyContainer::KeyContainer() :
	KeyContainer(ConstructNewKey())
{
}
