#include <sgx_tcrypto.h>

#include "../../Common/Ra/StatesSingleton.h"
#include "../../Common/Ra/KeyContainer.h"

using namespace Decent::Ra;

namespace
{
	static States& gs_state = GetStateSingleton();
}

extern "C" int ecall_decent_sgx_sp_get_pub_sign_key(sgx_ec256_public_t* out_key)
{
	std::shared_ptr<const general_secp256r1_public_t> pubKey(gs_state.GetKeyContainer().GetSignPubKey());
	if (!out_key || !pubKey)
	{
		return false;
	}

	std::memcpy(out_key, pubKey.get(), sizeof(general_secp256r1_public_t));
	return true;
}