#pragma once

#include "TlsConfig.h"

namespace Decent
{
	namespace Ra
	{
		/**
		 * \brief	The Decent RA TLS configuration that accept TLS connection with the peer that has the
		 * 			expected application name in the white list.
		 */
		class TlsConfigWithName : public TlsConfig
		{
		public:
			TlsConfigWithName(States& state, Mode cntMode, const std::string& expectedAppName);

			TlsConfigWithName(const TlsConfigWithName&) = delete;

			TlsConfigWithName(TlsConfigWithName&& rhs);

			virtual ~TlsConfigWithName();

			const std::string& GetExpectedAppName() const { return m_expectedAppName; }

		protected:
			virtual int VerifyDecentAppCert(const AppX509& cert, int depth, uint32_t& flag) const override;

		private:
			std::string m_expectedAppName;

		};
	}
}
