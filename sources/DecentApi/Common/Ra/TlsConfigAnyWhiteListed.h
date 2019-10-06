#pragma once

#include "TlsConfigBase.h"

namespace Decent
{
	namespace Ra
	{
		/**
		 * \brief	The Decent RA TLS configuration that accept TLS connection with any peer that is
		 * 			listed in the dynamic loaded white list.
		 */
		class TlsConfigAnyWhiteListed : public TlsConfigBase
		{
		public:
			using TlsConfigBase::TlsConfigBase;

		protected:
			virtual int VerifyDecentAppCert(const AppX509Cert& cert, int depth, uint32_t& flag) const override;

		};
	}
}
