#include "../../common/CryptoKeyContainer.h"
#include <sgx_tcrypto.h>

extern "C" int ecall_enclave_get_pub_sign_key(sgx_ec256_public_t* out_key)
{
	std::shared_ptr<const general_secp256r1_public_t> pubKey(CryptoKeyContainer::GetInstance().GetSignPubKey());
	if (!out_key || !pubKey)
	{
		return false;
	}

	std::memcpy(out_key, pubKey.get(), sizeof(general_secp256r1_public_t));
	return true;
}