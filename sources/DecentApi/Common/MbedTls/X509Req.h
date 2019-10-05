#pragma once

#include "ObjBase.h"

#include <vector>
#include <string>

typedef struct mbedtls_x509write_csr mbedtls_x509write_csr;
typedef struct mbedtls_x509_csr mbedtls_x509_csr;
typedef struct mbedtls_pk_context mbedtls_pk_context;

namespace Decent
{
	namespace MbedTlsObj
	{
		class AsymKeyBase;
		class RbgBase;

		class X509ReqWriter : public ObjBase<mbedtls_x509write_csr>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_x509write_csr* ptr);

			static size_t EstimateX509ReqDerSize(mbedtls_x509write_csr& ctx);

		public:

			/** \brief	Default constructor that constructs a non-null, valid, but empty X509 CSR Writer object. */
			X509ReqWriter();

			/**
			 * \brief	Constructor
			 *
			 * \param 		  	hashType  	Type of the hash.
			 * \param [in,out]	keyPair   	The key pair.
			 * \param 		  	commonName	Common Name.
			 */
			X509ReqWriter(HashType hashType, AsymKeyBase & keyPair, const std::string& commonName);

			X509ReqWriter(const X509ReqWriter& rhs) = delete;

			X509ReqWriter(X509ReqWriter&& rhs) = delete;

			/** \brief	Destructor */
			virtual ~X509ReqWriter();

			X509ReqWriter& operator=(const X509ReqWriter& rhs) = delete;

			X509ReqWriter& operator=(X509ReqWriter&& rhs) = delete;

			/**
			 * \brief	Generates a DER encoded X509 CSR.
			 *
			 * \param [in,out]	rbg	The Random Bit Generator.
			 *
			 * \return	The DER encoded X509 CSR.
			 */
			std::vector<uint8_t> GenerateDer(RbgBase& rbg);

			/**
			 * \brief	Generates a PEM encoded X509 CSR.
			 *
			 * \param [in,out]	rbg	The Random Bit Generator.
			 *
			 * \return	The PEM encoded X509 CSR.
			 */
			std::string GeneratePem(RbgBase& rbg);
		};

		class X509Req : public ObjBase<mbedtls_x509_csr>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_x509_csr* ptr);

		public:

			X509Req(const X509Req& rhs) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			X509Req(X509Req&& rhs);

			/**
			 * \brief	Constructs X509 Certificate Request from PEM encoded string.
			 *
			 * \param	pem	The PEM encoded string.
			 */
			X509Req(const std::string& pem);

			/**
			 * \brief	Constructs X509 Certificate Request from DER encoded bytes.
			 *
			 * \param	pem	The DER encoded bytes.
			 */
			X509Req(const std::vector<uint8_t>& der);

			/** \brief	Destructor */
			virtual ~X509Req();

			X509Req& operator=(const X509Req& rhs) = delete;

			X509Req& operator=(X509Req&& rhs);

			/**
			 * \brief	Gets the PEM encoded X509 Certificate Request.
			 *
			 * \return	The PEM.
			 */
			std::string GetPem() const;

			/**
			 * \brief	Gets the DER encoded X509 Certificate Request.
			 *
			 * \return	The DER.
			 */
			std::vector<uint8_t> GetDer() const;

			/**
			 * \brief	Gets the public key stored in the certificate request.
			 *
			 * \return	The public key.
			 */
			mbedtls_pk_context& GetPublicKey();

			/**
			 * \brief	Gets hash type used for the X509 Certificate Request.
			 *
			 * \return	The hash type.
			 */
			HashType GetHashType() const;

			/**
			 * \brief	Verifies this certificate request with the given public key.
			 *
			 * \param	pubKey	The pub key.
			 */
			void Verify(HashType hashType, AsymKeyBase& pubKey) const;

			/** \brief	Verifies this certificate request with the public key stored inside. */
			void Verify(HashType hashType);

		protected:

			/** \brief	Default constructor that constructs non-null, valid, but empty X509 CRL object. */
			X509Req();

			X509Req(mbedtls_x509_csr* ptr, FreeFuncType freeFunc);

		};
	}
}
