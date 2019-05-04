#pragma once

#include "../MbedTls/TlsConfig.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		class ECKeyPair;
		class X509Cert;
	}

	namespace Ra
	{
		class AppX509;
		class ServerX509;
		class States;

		/** \brief	This TLS configuration class is a base class for Decent RA TLS configurations. */
		class TlsConfig : public MbedTlsObj::TlsConfig
		{
		public: //Static member:
			enum class Mode
			{
				ServerVerifyPeer,   //This is server side, and it is required to verify peer's certificate.
				ServerNoVerifyPeer, //This is server side, and there is no need to verify peer's certificate.
				ClientHasCert,      //This is client side, and a certificate, which is required during TLS handshake, is possessed by the client.
				ClientNoCert,       //This is client side, and there is no certificate possessed by the client.
			};

		public:

			/**
			 * \brief	Constructor
			 *
			 * \param [in,out]	state	 	The Decent's global state.
			 * \param 		  	cntMode  	The connection mode.
			 * \param 		  	ticketMgr	Manager for session ticket.
			 */
			TlsConfig(States& state, Mode cntMode, std::shared_ptr<MbedTlsObj::SessionTicketMgrBase> ticketMgr);

			TlsConfig(TlsConfig&& other);

			TlsConfig(const TlsConfig& other) = delete;

			virtual ~TlsConfig();

			virtual TlsConfig& operator=(const TlsConfig& other) = delete;

			virtual TlsConfig& operator=(TlsConfig&& other) = delete;

			virtual operator bool() const noexcept override
			{
				return MbedTlsObj::TlsConfig::operator bool();
			}

			States& GetState() const { return m_state; }

		protected:
			virtual int VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const override;

			virtual int VerifyDecentServerCert(const ServerX509& cert, int depth, uint32_t& flag) const;
			virtual int VerifyDecentAppCert(const AppX509& cert, int depth, uint32_t& flag) const = 0;

		private:
			States& m_state;
			std::shared_ptr<const MbedTlsObj::ECKeyPair> m_prvKey;
			std::shared_ptr<const MbedTlsObj::X509Cert> m_cert;
		};
	}
}
