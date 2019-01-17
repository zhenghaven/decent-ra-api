#include "Crypto.h"

#include "../common/DataCoding.h"

const std::string & Decent::Crypto::GetSelfHashBase64()
{
	static const std::string hashBase64 = SerializeStruct(GetSelfHash().data(), GetSelfHash().size());

	return hashBase64;
}
