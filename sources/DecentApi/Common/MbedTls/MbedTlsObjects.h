#pragma once

#include <cstdint>

#include <string>
#include <vector>
#include <memory>
#include <map>

#include "ObjBase.h"
#include "../GeneralKeyTypes.h"

//For now, we put them together here.
#include "BigNumber.h"
#include "Gcm.h"
#include "AsymKeyBase.h"

typedef struct mbedtls_entropy_context mbedtls_entropy_context;
typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_ecp_keypair mbedtls_ecp_keypair;
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_x509_crl mbedtls_x509_crl;
typedef struct mbedtls_x509_crt_profile mbedtls_x509_crt_profile;
typedef struct mbedtls_md_info_t mbedtls_md_info_t;

namespace Decent
{
	namespace MbedTlsHelper
	{
		class MbedTlsInitializer;
	}

	namespace MbedTlsObj
	{
		class Drbg;
		class X509Req;

		class X509Cert : public ObjBase<mbedtls_x509_crt>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_x509_crt* ptr);

			static X509Cert FromPem(const std::string & pemStr);

			static std::string GeneratePemStr(const mbedtls_x509_crt& ref);

		public:

			/** \brief	Default constructor. Construct a empty and invalid instance. */
			X509Cert();

			X509Cert(const std::string& pemStr);

			X509Cert(mbedtls_x509_crt& ref);

			X509Cert(const X509Cert& caCert, const AsymKeyBase& prvKey, const AsymKeyBase& pubKey,
				const BigNumber& serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
				const std::string& x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap);

			X509Cert(const AsymKeyBase& prvKey,
				const BigNumber& serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
				const std::string& x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap);

			X509Cert(X509Cert&& other) : 
				ObjBase(std::forward<ObjBase>(other)),
				m_pubKey(std::move(other.m_pubKey)),
				m_certStack(std::move(other.m_certStack))
			{}

			X509Cert(const X509Cert& other) = delete;

			/** \brief	Destructor */
			virtual ~X509Cert() { SwitchToFirstCert(); }

			virtual X509Cert& operator=(const X509Cert& other) = delete;

			virtual X509Cert& operator=(X509Cert&& other) noexcept
			{
				ObjBase::operator=(std::forward<ObjBase>(other));

				if (this != &other)
				{
					m_pubKey = std::move(other.m_pubKey);
					m_certStack.swap(other.m_certStack);
				}
				return *this;
			}

			virtual operator bool() const noexcept override;

			bool GetExtensions(std::map<std::string, std::pair<bool, std::string> >& extMap) const;
			bool VerifySignature() const;
			bool VerifySignature(const AsymKeyBase& pubKey) const;

			bool Verify(const X509Cert& trustedCa, mbedtls_x509_crl* caCrl, const char* commonName,
				int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void* vrfyParam) const;
			bool Verify(const X509Cert& trustedCa, mbedtls_x509_crl* caCrl, const char* commonName, const mbedtls_x509_crt_profile& profile,
				int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void* vrfyParam) const;

			const AsymKeyBase& GetPublicKey() const;
			std::string ToPemString() const;

			std::string GetCommonName() const;

			bool NextCert();
			bool PreviousCert();
			void SwitchToFirstCert();

		protected:
			static X509Cert FromPemDer(const void* ptr, size_t size);

			X509Cert(mbedtls_x509_crt* ptr, FreeFuncType freeFunc);

		private:
			AsymKeyBase m_pubKey;
			std::vector<mbedtls_x509_crt*> m_certStack;
		};

		class EntropyCtx : public Decent::MbedTlsObj::ObjBase<mbedtls_entropy_context>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_entropy_context* ptr);

		public:
			EntropyCtx();
			virtual ~EntropyCtx() {}

		private:
			const MbedTlsHelper::MbedTlsInitializer& m_mbedTlsInit;

		};
	}
}
