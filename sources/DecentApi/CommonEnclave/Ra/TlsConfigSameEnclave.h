#pragma once

#include "../../Common/Ra/TlsConfig.h"

namespace Decent
{
	namespace Ra
	{
		/**
		 * \brief	The Decent RA TLS configuration that accept TLS connection with the peer that is the
		 * 			same enclave (i.e. same hash) as this one.
		 */
		class TlsConfigSameEnclave : public TlsConfig
		{
		public:
			using TlsConfig::TlsConfig;

		protected:
			virtual int VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const override;

			virtual int VerifyDecentAppCert(const AppX509& cert, int depth, uint32_t& flag) const override;

		private:

		};
	}
}
