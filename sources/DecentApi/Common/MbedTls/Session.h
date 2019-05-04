#pragma once

#include <memory>

#include "ObjBase.h"

typedef struct mbedtls_ssl_session mbedtls_ssl_session;

namespace Decent
{
	namespace MbedTlsObj
	{
		class Session : public ObjBase<mbedtls_ssl_session>
		{
		public: //static members:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_ssl_session* ptr);

		public:
			Session();

			virtual ~Session();

			Session(Session&&) = delete;

			Session(const Session&) = delete;

			Session& operator=(Session&&) = delete;

			Session& operator=(const Session&) = delete;
		};
	}
}