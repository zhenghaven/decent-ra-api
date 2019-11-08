#pragma once

#include <string>

#include "SafeWrappers.h"
#include "DataSizeGetters.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		namespace detail
		{
			void TlsPrf(HashType hashType, const void* key, size_t keySize, const char *label, const void* random, size_t randomSize, void* dest, size_t destSize);
		}

		/**
		 * \brief	TLS PRF
		 *
		 * \tparam	hashType		 	Type of the hash.
		 * \tparam	keySize			 	Size of the key.
		 * \tparam	RandContainerType	Type of the container for random.
		 * \tparam	ResContainerType 	Type of the container for result.
		 * \param 		  	key   	The key.
		 * \param 		  	label 	The label.
		 * \param 		  	random	The random.
		 * \param [in,out]	res   	The result (The size of res will be the output size).
		 */
		template<HashType hashType, size_t keySize, typename RandContainerType, typename ResContainerType,
			typename std::enable_if<detail::ContainerPrpt<RandContainerType>::sk_isSprtCtn &&
				detail::ContainerPrpt<ResContainerType>::sk_isSprtCtn, int>::type = 0>
		void TlsPrf(const SecretKeyWrap<keySize>& key, const std::string& label, const RandContainerType& random, ResContainerType& res)
		{
			return detail::TlsPrf(hashType, key.m_key.data(), key.m_key.size(), label.c_str(),
				detail::GetPtr(random), detail::GetSize(random),
				detail::GetPtr(res), detail::GetSize(res));
		}
	}
}
