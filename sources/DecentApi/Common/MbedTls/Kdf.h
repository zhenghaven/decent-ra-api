#pragma once

#include <array>
#include <string>

#include "MbedTlsCppDefs.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		void HKDF(HashType hashType, const void* inKey, size_t inKeyLen, const void* label, size_t labelLen, const void* inSalt, size_t inSaltLen, void* outKey, size_t outKeyLen);

		template<typename InKeyT, typename SaltT, typename OutKeyT>
		void HKDFStruct(HashType hashType, const InKeyT& inKey, const std::string& label, const SaltT& salt, OutKeyT& outKey)
		{
			HKDF(hashType, &inKey, sizeof(inKey), label.c_str(), label.size(), &salt, sizeof(salt), &outKey, sizeof(outKey));
		}

		template<typename InKeyT, typename SaltT, typename OutKeyT>
		void HKDF(HashType hashType, const InKeyT& inKey, const std::string& label, const SaltT& salt, OutKeyT& outKey)
		{
			HKDF(hashType, detail::GetPtr(inKey), detail::GetSize(inKey), label.c_str(), label.size(), detail::GetPtr(salt), detail::GetSize(salt), detail::GetPtr(outKey), detail::GetSize(outKey));
		}
	}
}
