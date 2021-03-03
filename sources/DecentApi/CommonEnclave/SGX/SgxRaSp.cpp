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
	if (out_key == nullptr)
	{
		return false;
	}

	auto keyPair = gs_state.GetKeyContainer().GetSignKeyPair();
	if (keyPair == nullptr)
	{
		return false;
	}

	std::array<uint8_t, sizeof(sgx_ec256_public_t::gx)> x;
	std::array<uint8_t, sizeof(sgx_ec256_public_t::gy)> y;
	std::tie(x, y, std::ignore) = keyPair->GetPublicBytes();

	std::copy(x.begin(), x.end(), std::begin(out_key->gx));
	std::copy(y.begin(), y.end(), std::begin(out_key->gy));

	return true;
}