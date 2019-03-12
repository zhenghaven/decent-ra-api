#include "Crypto.h"

#include <cppcodec/base64_default_rfc4648.hpp>

const std::string & Decent::Tools::GetSelfHashBase64()
{
	static const std::string hashBase64 = cppcodec::base64_rfc4648::encode(GetSelfHash());

	return hashBase64;
}
