#pragma once

#include <cstdint>

#include <string>
#include <vector>

#include "../../Common/GeneralKeyTypes.h"
#include "../../Common/ArrayPtrAndSize.h"

namespace Decent
{
	namespace Tools
	{

		/**
		 * \brief	Gets self hash in Base64 encoding.
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \return	The Base64 encoding string.
		 */
		const std::string& GetSelfHashBase64();

		/**
		 * \brief	Gets self hash in binary.
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \return	A binary array.
		 */
		const std::vector<uint8_t>& GetSelfHash();

		/**
		 * \brief	Secure random number generator. Usually enclave platform will provide a secure source
		 * 			to generate cryptographically secure random number.
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \param [out]	buf 	If non-null, the buffer to store the random number.
		 * \param 	   	size	The size of the buffer.
		 */
		void SecureRand(void* buf, size_t size);

		void PlatformAesGcmEncrypt(const void* keyPtr, const size_t keySize, const void* srcPtr, const size_t srcSize,
			void* destPtr,
			const void* ivPtr, const size_t ivSize,
			const void* addPtr, const size_t addSize,
			void* macPtr, const size_t macSize);

		void PlatformAesGcmDecrypt(const void* keyPtr, const size_t keySize, const void* srcPtr, const size_t srcSize,
			void* destPtr,
			const void* ivPtr, const size_t ivSize,
			const void* addPtr, const size_t addSize,
			const void* macPtr, const size_t macSize);
	}
}
