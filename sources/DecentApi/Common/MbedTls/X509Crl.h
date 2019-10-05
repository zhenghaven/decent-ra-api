#pragma once

#include "ObjBase.h"

#include <vector>
#include <string>

typedef struct mbedtls_x509_crl mbedtls_x509_crl;

namespace Decent
{
	namespace MbedTlsObj
	{
		class X509Crl : public ObjBase<mbedtls_x509_crl>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_x509_crl* ptr);

		public:

			X509Crl(const X509Crl& rhs) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			X509Crl(X509Crl&& rhs);

			/**
			 * \brief	Constructs X509 Certificate Revocation List from PEM encoded string.
			 *
			 * \param	pem	The PEM.
			 */
			X509Crl(const std::string& pem);

			/**
			 * \brief	Constructs X509 Certificate Revocation List from DER encoded binary.
			 *
			 * \param	pem	The DER.
			 */
			X509Crl(const std::vector<uint8_t>& der);

			/** \brief	Destructor */
			virtual ~X509Crl();

			/**
			 * \brief	Gets the PEM encoded X509 Certificate Revocation List
			 *
			 * \return	The PEM.
			 */
			std::string GetPem() const;

			/**
			 * \brief	Gets the DER encoded X509 Certificate Revocation List
			 *
			 * \return	The DER.
			 */
			std::vector<uint8_t> GetDer() const;

		protected:

			/** \brief	Default constructor that constructs non-null, valid, but empty X509 CRL object. */
			X509Crl();

			X509Crl(mbedtls_x509_crl* ptr, FreeFuncType freeFunc);

		};
	}
}
