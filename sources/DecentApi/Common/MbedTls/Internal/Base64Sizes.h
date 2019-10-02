#pragma once

#include <cstdint>

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			inline constexpr size_t CodecEncodedSize(bool hasPad, uint8_t binBlockSize, uint8_t encBlockSize, size_t binarySize) noexcept
			{
				// source: cppcodec
				return hasPad
					? (binarySize + (binBlockSize - 1)
						- ((binarySize + (binBlockSize - 1)) % binBlockSize))
					* encBlockSize / binBlockSize
					// No padding: only pad to the next multiple of 5 bits, i.e. at most a single extra byte.
					: (binarySize * encBlockSize / binBlockSize)
					+ (((binarySize * encBlockSize) % binBlockSize) ? 1 : 0);
			}

			inline constexpr size_t Base64EncodedSize(size_t binarySize) noexcept
			{
				return CodecEncodedSize(true, 3, 4, binarySize);
			}
		}
	}
}
