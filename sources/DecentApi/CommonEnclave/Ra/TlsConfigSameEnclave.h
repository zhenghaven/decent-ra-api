#pragma once

#include "../../Common/Ra/TlsConfigBase.h"

#include "../../Common/Ra/Crypto.h"
#include "../../Common/Ra/WhiteList/LoadedList.h"

#include "../Tools/Crypto.h"

namespace Decent
{
	namespace Ra
	{
		/**
		 * \brief	The Decent RA TLS configuration that accept TLS connection with the peer that is the
		 * 			same enclave (i.e. same hash) as this one.
		 */
		class TlsConfigSameEnclave : public TlsConfigBase
		{
		public: // Static members:

			using _Base = TlsConfigBase;

		public:

			TlsConfigSameEnclave(States& state,
				bool isServer, bool vrfyPeer,
				std::shared_ptr<mbedTLScpp::TlsSessTktMgrIntf> ticketMgr) :
				_Base::TlsConfigBase(state, isServer, vrfyPeer, ticketMgr)
			{}

			TlsConfigSameEnclave(TlsConfigSameEnclave&& other) :
				_Base::TlsConfigBase(std::forward<_Base>(other))
			{}

			TlsConfigSameEnclave(const TlsConfigSameEnclave& rhs) = delete;

			virtual ~TlsConfigSameEnclave()
			{}

			TlsConfigSameEnclave& operator=(const TlsConfigSameEnclave& rhs) = delete;

			TlsConfigSameEnclave& operator=(TlsConfigSameEnclave&& rhs) noexcept
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

				//Check peer's hash is same as self's hash.
				std::string peerHash = GetHashFromAppId(cert.GetPlatformType(), cert.GetAppId());
				if (Tools::GetSelfHashBase64() != peerHash)
				{
					flag = flag | MBEDTLS_X509_BADCERT_NOT_TRUSTED;
					return MBEDTLS_EXIT_SUCCESS;
				}

				//Check Loaded Lists are equivalent
				StaticList peerLoadedList(LoadedList::ParseWhiteListFromJson(cert.GetWhiteList()));
				if (peerLoadedList != GetState().GetLoadedWhiteList())
				{
					flag = flag | MBEDTLS_X509_BADCERT_NOT_TRUSTED;
					return MBEDTLS_EXIT_SUCCESS;
				}

				return MBEDTLS_EXIT_SUCCESS;
			}

		};
	}
}
