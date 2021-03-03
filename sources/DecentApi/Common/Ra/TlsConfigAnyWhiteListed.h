#pragma once

#include "TlsConfigBase.h"

#include "Crypto.h"
#include "WhiteList/LoadedList.h"

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
		public: // Static members:

			using _Base = TlsConfigBase;

		public:

			TlsConfigAnyWhiteListed(States& state,
				bool isServer, bool vrfyPeer,
				std::shared_ptr<mbedTLScpp::TlsSessTktMgrIntf> ticketMgr) :
				_Base::TlsConfigBase(state, isServer, vrfyPeer, ticketMgr)
			{}

			TlsConfigAnyWhiteListed(TlsConfigAnyWhiteListed&& other) :
				_Base::TlsConfigBase(std::forward<_Base>(other))
			{}

			TlsConfigAnyWhiteListed(const TlsConfigAnyWhiteListed& rhs) = delete;

			virtual ~TlsConfigAnyWhiteListed()
			{}

			TlsConfigAnyWhiteListed& operator=(const TlsConfigAnyWhiteListed& rhs) = delete;

			TlsConfigAnyWhiteListed& operator=(TlsConfigAnyWhiteListed&& rhs) noexcept
			{
				_Base::operator=(std::forward<_Base>(rhs)); //noexcept

				return *this;
			}

		protected:
			virtual int VerifyDecentAppCert(
				const AppX509CertBase<mbedTLScpp::BorrowedX509CertTrait>& cert,
				int depth, uint32_t& flag) const override
			{
				using namespace Decent::Ra::WhiteList;

				if (flag != 0x00)
				{
					//Decent Server cert is invalid! Directly return.
					return MBEDTLS_EXIT_SUCCESS;
				}

				//Check peer's hash is in the white list, while the app name is ignored.
				std::string peerHash = GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
				std::string appName;
				if (!GetState().GetLoadedWhiteList().CheckHash(peerHash, appName))
				{
					flag = flag | MBEDTLS_X509_BADCERT_NOT_TRUSTED;
					return MBEDTLS_EXIT_SUCCESS;
				}

				//Check Loaded Lists are equivalent
				StaticList peerLoadedList(LoadedList::ParseWhiteListFromJson(cert.GetWhiteList()));
				if (peerLoadedList != GetState().GetLoadedWhiteList())
				{
					PRINT_I("Peer's AuthList does not match.\n\tPeer's AuthList %s.\n\tOur AuthList: %s.",
						cert.GetWhiteList().c_str(), GetState().GetLoadedWhiteList().ToJsonString().c_str());
					flag = flag | MBEDTLS_X509_BADCERT_NOT_TRUSTED;
					return MBEDTLS_EXIT_SUCCESS;
				}

				return MBEDTLS_EXIT_SUCCESS;
			}
		};
	}
}
