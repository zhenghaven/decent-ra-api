#pragma once

#include "TlsConfigBase.h"

#include "Crypto.h"
#include "WhiteList/LoadedList.h"

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
		public: // Static members:

			using _Base = TlsConfigBase;

		public:
			TlsConfigWithName(States& state,
				bool isServer, bool vrfyPeer,
				const std::string& expectedAppName,
				std::shared_ptr<mbedTLScpp::TlsSessTktMgrIntf> ticketMgr) :
				_Base::TlsConfigBase(state,
					isServer, vrfyPeer,
					ticketMgr),
				m_expectedAppName(expectedAppName)
			{}

			TlsConfigWithName(const TlsConfigWithName&) = delete;

			TlsConfigWithName(TlsConfigWithName&& rhs) :
				_Base::TlsConfigBase(std::forward<_Base>(rhs)),
				m_expectedAppName(std::move(rhs.m_expectedAppName))
			{}

			virtual ~TlsConfigWithName()
			{}

			TlsConfigWithName& operator=(const TlsConfigWithName& rhs) = delete;

			TlsConfigWithName& operator=(TlsConfigWithName&& rhs)
			{
				_Base::operator=(std::forward<_Base>(rhs)); //noexcept

				if (this != &rhs)
				{
					m_expectedAppName = std::move(m_expectedAppName);
				}

				return *this;
			}

			const std::string& GetExpectedAppName() const
			{
				return m_expectedAppName;
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

				//Check peer's hash is in the white list, and the app name is matched.
				std::string peerHash = GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
				if (!GetState().GetLoadedWhiteList().CheckHashAndName(peerHash, m_expectedAppName))
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

		private:
			std::string m_expectedAppName;
		};
	}
}
