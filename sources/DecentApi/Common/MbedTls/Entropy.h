#pragma once

#include "ObjBase.h"

typedef struct mbedtls_entropy_context mbedtls_entropy_context;

namespace Decent
{
	namespace MbedTlsObj
	{
		class Entropy : public ObjBase<mbedtls_entropy_context>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_entropy_context* ptr);

			/**
			 * \brief	Initializes the shared entropy, which can be used by different DRBG instance, and
			 * 			different threads. It's thread-safe since mbedTLS entropy is using mutex.
			 *
			 * \return	A reference to the shared entropy.
			 */
			static Entropy& InitSharedEntropy();

		public:
			Entropy();

			virtual ~Entropy() {}

		};
	}
}
