#pragma once

#include "TlsConfig.h"

namespace Decent
{
	namespace Ra
	{
		/**
		 * \brief	The Decent RA TLS configuration that accept TLS connection with any peer that is
		 * 			listed in the dynamic loaded white list.
		 */
		class TlsConfigAnyWhiteListed : public TlsConfig
		{
		public:
			using TlsConfig::TlsConfig;

		protected:
			virtual int VerifyDecentAppCert(const AppX509& cert, int depth, uint32_t& flag) const override;

		private:

		};
	}
}
