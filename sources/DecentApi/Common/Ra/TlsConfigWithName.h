#pragma once

#include "TlsConfigBase.h"

namespace Decent
{
	namespace Ra
	{
		/**
		 * \brief	The Decent RA TLS configuration that accept TLS connection with the peer that has the
		 * 			expected application name in the white list.
		 */
		class TlsConfigWithName : public TlsConfigBase
		{
		public:
			TlsConfigWithName(States& state, Mode cntMode, const std::string& expectedAppName, std::shared_ptr<MbedTlsObj::SessionTicketMgrBase> ticketMgr);

			TlsConfigWithName(const TlsConfigWithName&) = delete;

			TlsConfigWithName(TlsConfigWithName&& rhs);

			virtual ~TlsConfigWithName();

			const std::string& GetExpectedAppName() const { return m_expectedAppName; }

		protected:
			virtual int VerifyDecentAppCert(const AppX509Cert& cert, int depth, uint32_t& flag) const override;

		private:
			std::string m_expectedAppName;

		};
	}
}
