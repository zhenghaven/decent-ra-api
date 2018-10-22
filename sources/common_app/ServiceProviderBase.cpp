#include "ServiceProviderBase.h"

#include "../common/DataCoding.h"
#include "../common/GeneralKeyTypes.h"

const std::string ServiceProviderBase::GetSpPublicSignKey() const
{
	general_secp256r1_public_t signPubKey;
	GetSpPublicSignKey(signPubKey);
	return SerializeStruct(signPubKey);
}
