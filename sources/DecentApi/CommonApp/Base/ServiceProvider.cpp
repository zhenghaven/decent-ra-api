#include "ServiceProvider.h"

#include "../../Common/Tools/DataCoding.h"
#include "../../Common/GeneralKeyTypes.h"

using namespace Decent::Tools;
using namespace Decent::Base;

const std::string ServiceProvider::GetSpPublicSignKey() const
{
	general_secp256r1_public_t signPubKey;
	GetSpPublicSignKey(signPubKey);
	return SerializeStruct(signPubKey);
}
