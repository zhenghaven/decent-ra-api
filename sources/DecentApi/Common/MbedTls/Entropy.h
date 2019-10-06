#pragma once

#include "ObjBase.h"

typedef struct mbedtls_entropy_context mbedtls_entropy_context;

namespace Decent
{
	namespace MbedTlsObj
	{
		class Initializer;

		class Entropy : public ObjBase<mbedtls_entropy_context>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_entropy_context* ptr);

			static Entropy& InitSharedEntropy();

		public:
			Entropy();

			virtual ~Entropy() {}

		private:
			const Initializer& m_mbedTlsInit;

		};
	}
}
