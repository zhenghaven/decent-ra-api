#pragma once

#include "ObjBase.h"

#include <map>
#include <vector>
#include <string>

typedef struct mbedtls_x509write_cert mbedtls_x509write_cert;
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_x509_crl mbedtls_x509_crl;
typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_x509_crt_profile mbedtls_x509_crt_profile;

namespace Decent
{
	namespace MbedTlsObj
	{
		class RbgBase;
		class X509Cert;
		class BigNumber;
		class AsymKeyBase;

		class X509CertWriter : public ObjBase<mbedtls_x509write_cert>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_x509write_cert* ptr);

			static size_t EstimateX509CertDerSize(mbedtls_x509write_cert& ctx);

		public:

			/** \brief	Default constructor that constructs a non-null, valid, but empty X509 Cert Writer object. */
			X509CertWriter();

			/**
			 * \brief	Constructs a self-signed certificate.
			 *
			 * \param 		  	hashType	Type of the hash.
			 * \param [in,out]	prvKey  	The key pair including private key.
			 * \param 		  	subjName	Subject name for a Certificate. A comma-separated list of OID
			 * 								types and values (e.g. "C=UK,O=ARM,CN=mbed TLS Server 1").
			 */
			X509CertWriter(HashType hashType, AsymKeyBase& prvKey, const std::string& subjName);

			/**
			 * \brief	Issue certificate with the given public key.
			 *
			 * \param 		  	hashType	Type of the hash.
			 * \param 		  	caCert  	The certificate of the CA.
			 * \param [in,out]	prvKey  	The key pair including private key.
			 * \param [in,out]	pubKey  	The public key.
			 * \param 		  	subjName	Subject name for a Certificate. A comma-separated list of OID
			 * 								types and values (e.g. "C=UK,O=ARM,CN=mbed TLS Server 1").
			 */
			X509CertWriter(HashType hashType, const X509Cert& caCert, AsymKeyBase& prvKey, AsymKeyBase& pubKey, const std::string& subjName);

			X509CertWriter(const X509CertWriter& rhs) = delete;

			X509CertWriter(X509CertWriter&& rhs) = delete;

			/** \brief	Destructor */
			virtual ~X509CertWriter();

			X509CertWriter& operator=(const X509CertWriter& rhs) = delete;

			X509CertWriter& operator=(X509CertWriter&& rhs) = delete;

			/**
			 * \brief	Sets serial number
			 *
			 * \param	serialNum	The serial number.
			 */
			void SetSerialNum(const BigNumber& serialNum);

			/**
			 * \brief	Sets validation time
			 *
			 * \param	validSince 	The time since when the certificate is valid. (Format, a string:
			 * 						YYYYMMDDHHMMSS)
			 * \param	expireAfter	The time after when the certificate is expired.  (Format, a string:
			 * 						YYYYMMDDHHMMSS)
			 */
			void SetValidationTime(const std::string& validSince, const std::string& expireAfter);

			/**
			 * \brief	Sets basic constraints.
			 *
			 * \param	isCa		 	True if is CA, false if not.
			 * \param	maxChainDepth	The maximum chain depth.
			 */
			void SetBasicConstraints(bool isCa, int maxChainDepth);

			/**
			 * \brief	Sets key usage flags.
			 *
			 * \param	keyUsage	The key usage flags.
			 */
			void SetKeyUsage(unsigned int keyUsage);

			/**
			 * \brief	Sets Netscape Cert type flags.
			 *
			 * \param	nsType	Netscape Cert Type flags.
			 */
			void SetNsType(unsigned char nsType);

			/**
			 * \brief	Sets x509 V3 extensions list. Extensions in v3ExtMap will be added to the certificate,
			 * 			if OID already exist, the value will be updated to the one in v3ExtMap.
			 *
			 * \param	v3ExtMap	The x509 V3 extensions list.
			 */
			void SetV3Extensions(const std::map<std::string, std::pair<bool, std::string> >& v3ExtMap);

			/**
			 * \brief	Generates a DER encoded X509 Cert.
			 *
			 * \param [in,out]	rbg	The Random Bit Generator.
			 *
			 * \return	The DER encoded X509 Cert.
			 */
			std::vector<uint8_t> GenerateDer(RbgBase& rbg);

			/**
			 * \brief	Generates a PEM encoded X509 Cert.
			 *
			 * \param [in,out]	rbg	The Random Bit Generator.
			 *
			 * \return	The PEM encoded X509 Cert.
			 */
			std::string GeneratePem(RbgBase& rbg);

			/**
			 * \brief	Generates a certificate chain including the CA.
			 *
			 * \param [in,out]	rbg	The Random Bit Generator.
			 *
			 * \return	The PEM encoded X509 Cert chain.
			 */
			std::string GeneratePemChain(RbgBase& rbg);

		private:
			std::unique_ptr<X509Cert> m_ca;
		};

		class X509Cert : public ObjBase<mbedtls_x509_crt>
		{
		public: //static member:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_x509_crt* ptr);

			/** \brief	Defines an alias representing the VerifyFunc used for certificate chain verification. */
			typedef int(*VerifyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *);

		public:

			/**
			 * \brief	Copy constructor
			 *
			 * \param	rhs	The right hand side.
			 */
			X509Cert(const X509Cert& rhs);

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			X509Cert(X509Cert&& rhs);

			/**
			 * \brief	Constructs X509 Certificate from PEM encoded string.
			 *
			 * \param	pem	The PEM encoded string.
			 */
			X509Cert(const std::string& pem);

			/**
			 * \brief	Constructs X509 Certificate from DER encoded bytes.
			 *
			 * \param	pem	The DER encoded bytes.
			 */
			X509Cert(const std::vector<uint8_t>& der);

			/**
			 * \brief	Constructs a instance that refer to an existing mbedTLS X509 Certificate object.
			 *
			 * \warning	This instance does not own the object, so that please make sure the life time
			 * 			of the given context is longer than this instance.
			 *
			 * \param [in,out]	ref	The reference.
			 */
			X509Cert(mbedtls_x509_crt& ref);

			/** \brief	Destructor */
			virtual ~X509Cert();

			X509Cert& operator=(const X509Cert& rhs) = delete;

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			X509Cert& operator=(X509Cert&& rhs);

			/**
			 * \brief	Query if this instance is in null state (either pointer to the mbedTLS object is null,
			 * 			or the pointer to the current certificate is null).
			 *
			 * \return	True if null, false if not.
			 */
			virtual bool IsNull() const override;

			/**
			 * \brief	Gets the pointer to the current pointed certificate in the chain.
			 *
			 * \return	Null if it fails, else the curr.
			 */
			mbedtls_x509_crt* GetCurr();

			/**
			 * \brief	Gets the pointer to the current pointed certificate in the chain.
			 *
			 * \return	Null if it fails, else the curr.
			 */
			const mbedtls_x509_crt* GetCurr() const;

			/**
			 * \brief	Gets the DER encoded X509 Certificate.
			 *
			 * \return	The DER.
			 */
			std::vector<uint8_t> GetCurrDer() const;

			/**
			 * \brief	Gets the PEM encoded X509 Certificate for the X509 Cert object pointed currently.
			 *
			 * \return	The PEM.
			 */
			std::string GetCurrPem() const;

			/**
			 * \brief	Gets the PEM encoded X509 Certificates of the entire chain. PEM strings are
			 * 			concatenated one after another, from the first cert on the chain to the last one.
			 *
			 * \return	The series of PEM encoded X509 Certificates.
			 */
			std::string GetPemChain() const;

			/**
			 * \brief	Gets the public key stored in the certificate.
			 *
			 * \return	The public key.
			 */
			mbedtls_pk_context& GetCurrPublicKey();

			/**
			 * \brief	Gets hash type used for the X509 Certificate.
			 *
			 * \return	The hash type.
			 */
			HashType GetCurrHashType() const;

			/**
			 * \brief	Gets the common name of the current certificate.
			 *
			 * \return	The common name of the current certificate.
			 */
			std::string GetCurrCommonName() const;

			/**
			 * \brief	Only verifies the signature on the current certificate with the given public key.
			 *
			 * \param [in,out]	pubKey	The public key.
			 */
			void VerifyCurrSignature(AsymKeyBase& pubKey) const;

			/**
			 * \brief	Only verifies the signature on the current certificate with the public key signed in
			 * 			this certificate (i.e. self-signed certificate).
			 */
			void VerifyCurrSignature();

			/**
			 * \brief	Gets X509 V3 extensions. The returning map is in the format of {"OID" : &lt;
			 * 			is_critical, "value"&gt;}. This method will iterate through the entire extension list
			 * 			and store all extensions into the map.
			 *
			 * \return	The a map holding V3 extensions.
			 */
			std::map<std::string, std::pair<bool, std::string> > GetCurrV3Extensions() const;

			/**
			 * \brief	Gets a specific X509 V3 extension. This method will iterate through the entire
			 * 			extension list, but once the given OID is found, the corresponding value will be
			 * 			returned.
			 *
			 * \param	oid	The OID of the extension.
			 *
			 * \return	A pair of &lt;is_critical, "value"&gt;.
			 */
			std::pair<bool, std::string> GetCurrV3Extension(const std::string& oid) const;

			/**
			 * \brief	Verify the certificate chain with given trusted CA(s).
			 *
			 * \param [in,out]	ca		 	The trusted CA(s), which could be a chain including a list of CAs.
			 * \param [in,out]	crl		 	If non-null, the list of CRLs for trusted CAs.
			 * \param 		  	cn		 	If non-null, the expected Common Name. If null, the Common Name
			 * 								will not be verified.
			 * \param [out]	  	flags	 	The flags representing verification result. If the resultant flag
			 * 								is not zero, exception will be thrown, but, this flag will be set
			 * 								before thrown.
			 * \param 		  	prof	 	The security profile for verification.
			 * \param 		  	vrfyFunc 	The vrfy function.
			 * \param [in,out]	vrfyParam	If non-null, the vrfy parameter.
			 */
			void VerifyChainWithCa(X509Cert& ca, mbedtls_x509_crl* crl, const char* cn, uint32_t& flags,
				const mbedtls_x509_crt_profile& prof, VerifyFunc vrfyFunc, void* vrfyParam);

			/**
			 * \brief	Go to the next certificate in the chain.
			 *
			 * \return	True if it succeeds, false if there is no next one.
			 */
			bool NextCert();

			/**
			 * \brief	Go to the previous certificate in the chain.
			 *
			 * \return	True if it succeeds, false if it is already in the first one.
			 */
			bool PrevCert();

			/** \brief	Go to first certificate in the chain. */
			void GoToFirstCert();

			/** \brief	Go to last certificate in the chain. */
			void GoToLastCert();

		protected:

			/** \brief	Default constructor that constructs non-null, valid, but empty X509 CRT object. */
			X509Cert();

			X509Cert(mbedtls_x509_crt* ptr, FreeFuncType freeFunc);

		private:

			mbedtls_x509_crt* m_currCert;
			std::vector<mbedtls_x509_crt*> m_certStack;
		};
	}
}
