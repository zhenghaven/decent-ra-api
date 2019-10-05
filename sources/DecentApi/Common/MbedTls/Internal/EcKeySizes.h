#pragma once

#include <cstdint>

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			//################################
			//   Helper Functions
			//################################

			inline constexpr size_t CalcEcpPubDerSize(size_t sizeInByte)
			{
				return (30 + 2 * sizeInByte);
			}

			inline constexpr size_t CalcEcpPrvDerSize(size_t sizeInByte)
			{
				return (29 + 3 * sizeInByte);
			}
		}
	}
}