#include "Crypto.h"

#include "../../Common/Tools/DataCoding.h"

using namespace Decent::Tools;

const std::string & Decent::Crypto::GetSelfHashBase64()
{
	static const std::string hashBase64 = SerializeStruct(GetSelfHash().data(), GetSelfHash().size());

	return hashBase64;
}
