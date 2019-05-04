#pragma once

#include <memory>

#include "ObjBase.h"

typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_ssl_config mbedtls_ssl_config;

namespace Decent
{
	namespace MbedTlsObj
	{
		class Drbg;
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

		public:

			/**
			 * \brief	Default constructor that will create and initialize an TLS configuration. Both DRBG
			 * 			and verification callback function are set here.
			 */
			TlsConfig(std::shared_ptr<SessionTicketMgrBase> ticketMgr);

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			TlsConfig(TlsConfig&& rhs);

			TlsConfig(const TlsConfig& rhs) = delete;

			/** \brief	Destructor */
			virtual ~TlsConfig();

			virtual TlsConfig& operator=(const TlsConfig& rhs) = delete;

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this object.
			 */
			virtual TlsConfig& operator=(TlsConfig&& rhs) noexcept;

			/**
			 * \brief	Check if this instance is valid (i.e. ObjBase is valid, and DRBG is valid). 
			 *
			 * \return	True if this instance is valid, otherwise, false.
			 */
			virtual operator bool() const noexcept override;

		protected:

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
			std::unique_ptr<Decent::MbedTlsObj::Drbg> m_rng;
			std::shared_ptr<SessionTicketMgrBase> m_ticketMgr;
		};
	}
}
