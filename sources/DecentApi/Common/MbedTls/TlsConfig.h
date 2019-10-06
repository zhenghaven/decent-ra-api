#pragma once

#include <memory>

#include "ObjBase.h"

typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_ssl_config mbedtls_ssl_config;

namespace Decent
{
	namespace MbedTlsObj
	{
		class RbgBase;
		class AsymKeyBase;
		class X509Cert;
		class SessionTicketMgrBase;

		class TlsConfig : public ObjBase<mbedtls_ssl_config>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_ssl_config* ptr);

			/**
			 * \brief	Certificate verify call back function that is given to the MbedTLS's certificate
			 * 			verification function call.
			 *
			 * \param [in,out]	inst 	The pointer to 'this instance'. Must be not null.
			 * \param [in,out]	cert 	The pointer to MbedTLS's certificate. Must be not null.
			 * \param 		  	depth	The depth of current verification along the certificate chain.
			 * \param [in,out]	flag 	The flag of verification result. Please refer to MbedTLS's API for details.
			 *
			 * \return	The verification error code return.
			 */
			static int CertVerifyCallBack(void* inst, mbedtls_x509_crt* cert, int depth, uint32_t* flag) noexcept;

			enum class Mode
			{
				ServerVerifyPeer,   //This is server side, and it is required to verify peer's certificate.
				ServerNoVerifyPeer, //This is server side, and there is no need to verify peer's certificate.
				ClientHasCert,      //This is client side, and a certificate, which is required during TLS handshake, is possessed by the client.
				ClientNoCert,       //This is client side, and there is no certificate possessed by the client.
			};

		public:

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			TlsConfig(TlsConfig&& rhs);

			TlsConfig(const TlsConfig& rhs) = delete;

			/**
			 * \brief	Default constructor that will create and initialize an TLS configuration. Both DRBG
			 * 			and verification callback function are set here.
			 *
			 * \param	isStream 	True if transport layer is stream (TLS), false if not (DTLS).
			 * \param	cntMode  	The connection mode.
			 * \param	preset   	The preset. Please refer to mbedTLS mbedtls_ssl_config_defaults.
			 * \param	rbg		 	The Random Bit Generator.
			 * \param	ca		 	The CA.
			 * \param	cert	 	The certificate.
			 * \param	prvKey   	The private key.
			 * \param	ticketMgr	Manager for TLS ticket.
			 */
			TlsConfig(bool isStream, Mode cntMode, int preset, std::unique_ptr<RbgBase> rbg,
				std::shared_ptr<const X509Cert> ca, std::shared_ptr<const X509Cert> cert, std::shared_ptr<const AsymKeyBase> prvKey,
				std::shared_ptr<SessionTicketMgrBase> ticketMgr);

			/** \brief	Destructor */
			virtual ~TlsConfig();

			TlsConfig& operator=(const TlsConfig& rhs) = delete;

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this object.
			 */
			TlsConfig& operator=(TlsConfig&& rhs);

			/**
			 * \brief	Query if the pointers to objects held by this object is null
			 *
			 * \return	True if null, false if not.
			 */
			virtual bool IsNull() const noexcept;

		protected:

			/**
			 * \brief	Constructs an non-null, valid, but empty TLS config context.
			 *
			 * \param	rbg		 	The Random Bit Generator.
			 * \param	ca		 	The CA.
			 * \param	cert	 	The certificate.
			 * \param	prvKey   	The private key.
			 * \param	ticketMgr	Manager for TLS ticket.
			 */
			TlsConfig(std::unique_ptr<RbgBase> rbg,
				std::shared_ptr<const X509Cert> ca, std::shared_ptr<const X509Cert> cert, std::shared_ptr<const AsymKeyBase> prvKey,
				std::shared_ptr<SessionTicketMgrBase> ticketMgr);

			/**
			 * \brief	Verify the certificate given by the MbedTLS verification callback. Note: this
			 * 			function and any underlying calls may throw exceptions, but, they will be caught by
			 * 			the static callback function (i.e. CertVerifyCallBack), and return an error code
			 * 			instead.
			 *
			 * \param [in,out]	cert 	The certificate.
			 * \param 		  	depth	The depth of current verification along the certificate chain.
			 * \param [in,out]	flag 	The flag of verification result. Please refer to MbedTLS's API for
			 * 							details.
			 *
			 * \return	The verification error code return.
			 */
			virtual int VerifyCert(mbedtls_x509_crt& cert, int depth, uint32_t& flag) const = 0;

		private:
			std::unique_ptr<RbgBase> m_rng;
			std::shared_ptr<const X509Cert> m_ca;
			std::shared_ptr<const X509Cert> m_cert;
			std::shared_ptr<const AsymKeyBase> m_prvKey;
			std::shared_ptr<SessionTicketMgrBase> m_ticketMgr;
		};
	}
}
