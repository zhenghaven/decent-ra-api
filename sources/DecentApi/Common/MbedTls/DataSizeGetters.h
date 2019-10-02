#pragma once

#include "MbedTlsCppDefs.h"
#include "RuntimeException.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		/**
		 * \brief	Gets hash size in Byte
		 *
		 * \exception	RuntimeException	Thrown when a nonexistent hash type is given.
		 *
		 * \param	type	Type of the hash.
		 *
		 * \return	The hash size in Byte.
		 */
		inline constexpr uint8_t GetHashByteSize(HashType type)
		{
			switch (type)
			{
			case HashType::SHA224:
				return (224 / BITS_PER_BYTE);
			case HashType::SHA256:
				return (256 / BITS_PER_BYTE);
			case HashType::SHA384:
				return (384 / BITS_PER_BYTE);
			case HashType::SHA512:
				return (512 / BITS_PER_BYTE);
			default:
				throw RuntimeException("Invalid hash type is given!");
			}
		}
	}
}
