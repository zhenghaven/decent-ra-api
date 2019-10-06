#pragma once

#include "../MbedTls/TlsConfig.h"

namespace Decent
{
	namespace Ra
	{
		class AppX509Cert;
		class ServerX509Cert;
		class States;

		/** \brief	This TLS configuration class is a base class for Decent RA TLS configurations. */
		class TlsConfigBase : public MbedTlsObj::TlsConfig
		{
		public:

			/**
			 * \brief	Constructor
			 *
			 * \param [in,out]	state	 	The Decent's global state.
			 * \param 		  	cntMode  	The connection mode.
			 * \param 		  	ticketMgr	Manager for session ticket.
			 */
			TlsConfigBase(States& state, Mode cntMode, std::shared_ptr<MbedTlsObj::SessionTicketMgrBase> ticketMgr);

			TlsConfigBase(TlsConfigBase&& rhs);

			TlsConfigBase(const TlsConfigBase& rhs) = delete;

			virtual ~TlsConfigBase();

			virtual TlsConfigBase& operator=(const TlsConfigBase& rhs) = delete;

			virtual TlsConfigBase& operator=(TlsConfigBase&& rhs) = delete;

			States& GetState() const { return m_state; }

		protected:
			virtual int VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const override;

			virtual int VerifyDecentServerCert(const ServerX509Cert& cert, int depth, uint32_t& flag) const;

			virtual int VerifyDecentAppCert(const AppX509Cert& cert, int depth, uint32_t& flag) const = 0;

		private:
			States& m_state;
		};
	}
}
