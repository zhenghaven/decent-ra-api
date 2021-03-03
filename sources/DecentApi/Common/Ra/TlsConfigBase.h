#pragma once

#include <mbedTLScpp/TlsConfig.hpp>

#include "States.h"
#include "../Ra/CertContainer.h"
#include "../Ra/KeyContainer.h"
#include "../Ra/WhiteList/DecentServer.h"

#include "ServerX509Cert.h"
#include "AppX509Cert.h"

namespace Decent
{
	namespace Ra
	{
		/** \brief	This TLS configuration class is a base class for Decent RA TLS configurations. */
		class TlsConfigBase : public mbedTLScpp::TlsConfig
		{
		public: // Static members:

			using _Base = mbedTLScpp::TlsConfig;
		
		public:

			/**
			 * \brief	Constructor
			 *
			 * \param [in,out]	state	 	The Decent's global state.
			 * \param 		  	cntMode  	The connection mode.
			 * \param 		  	ticketMgr	Manager for session ticket.
			 */
			TlsConfigBase(States& state,
				bool isServer, bool vrfyPeer,
				std::shared_ptr<mbedTLScpp::TlsSessTktMgrIntf> ticketMgr) :
				_Base::TlsConfig(true, isServer, vrfyPeer, MBEDTLS_SSL_PRESET_SUITEB,
					state.GetCertContainer().GetCert(), nullptr, state.GetCertContainer().GetCert(),
					state.GetKeyContainer().GetSignKeyPair(), ticketMgr),
				m_state(&state)
			{}

			TlsConfigBase(TlsConfigBase&& other) :
				_Base::TlsConfig(std::forward<_Base>(other)),
				m_state(other.m_state)
			{}

			TlsConfigBase(const TlsConfigBase& rhs) = delete;

			virtual ~TlsConfigBase()
			{}

			virtual bool IsNull() const noexcept override
			{
				return _Base::IsNull() ||
					(m_state == nullptr);
			}

			TlsConfigBase& operator=(const TlsConfigBase& rhs) = delete;

			TlsConfigBase& operator=(TlsConfigBase&& rhs) noexcept
			{
				_Base::operator=(std::forward<_Base>(rhs)); //noexcept

				if (this != &rhs)
				{
					m_state = rhs.m_state; //noexcept

					rhs.m_state = nullptr; //noexcept
				}

				return *this;
			}

			States& GetState() const
			{
				return *m_state;
			}

		protected:
			virtual int CustomVerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const override
			{
				using namespace mbedTLScpp;

				switch (depth)
				{
				case 0: //Decent App Cert
				{
					const AppX509CertBase<BorrowedX509CertTrait> appCert(&cert);

					return VerifyDecentAppCert(appCert, depth, flag);
				}
				case 1: //Decent Server Cert
				{
					const ServerX509CertBase<BorrowedX509CertTrait> serverCert(&cert);

					return VerifyDecentServerCert(serverCert, depth, flag);
				}
				default:
					return MBEDTLS_ERR_X509_FATAL_ERROR;
				}
			}

			virtual int VerifyDecentServerCert(
				const ServerX509CertBase<mbedTLScpp::BorrowedX509CertTrait>& cert, int depth, uint32_t& flag) const
			{
				if (m_state == nullptr)
				{
					return MBEDTLS_ERR_X509_FATAL_ERROR;
				}
				const bool verifyRes = m_state->GetServerWhiteList().AddTrustedNode(*m_state, cert);
				flag = verifyRes ? MBEDTLS_EXIT_SUCCESS : MBEDTLS_X509_BADCERT_NOT_TRUSTED;
				return MBEDTLS_EXIT_SUCCESS;
			}

			virtual int VerifyDecentAppCert(
				const AppX509CertBase<mbedTLScpp::BorrowedX509CertTrait>& cert, int depth, uint32_t& flag) const = 0;

		private:
			States* m_state;
		};
	}
}
