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

			inline constexpr size_t CalcRsaPubDerSize(size_t sizeInByte)
			{
				return (38 + 2 * sizeInByte);
			}
		}
	}
}