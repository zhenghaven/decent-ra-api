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

typedef struct mbedtls_entropy_context mbedtls_entropy_context;
typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_ecp_keypair mbedtls_ecp_keypair;
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_x509_csr mbedtls_x509_csr;
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

		class PKey : public ObjBase<mbedtls_pk_context>
		{
		public:
			/**
			 * \brief	Function that frees MbedTLS object and delete the pointer.
			 *
			 * \param [in,out]	ptr	If non-null, the pointer.
			 */
			static void FreeObject(mbedtls_pk_context* ptr);

			static PKey Empty() { return PKey(nullptr, &ObjBase::DoNotFree); }

		public:
			/**
			 * \brief	Constructor that accept a reference to mbedtls_pk_context object, thus, this instance doesn't
			 * 			has the ownership.
			 *
			 * \param [in,out]	ref	The reference.
			 */
			PKey(mbedtls_pk_context& ref) noexcept :
				ObjBase(&ref, &ObjBase::DoNotFree)
			{}

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	other	The other.
			 */
			PKey(PKey&& other) noexcept :
				ObjBase(std::forward<ObjBase>(other))
			{}

			/** \brief	Destructor */
			virtual ~PKey() {}

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	other	The other.
			 *
			 * \return	A reference to this object.
			 */
			virtual PKey& operator=(PKey&& other)
			{
				ObjBase::operator=(std::forward<ObjBase>(other));
				return  *this;
			}

			/**
			 * \brief	Verify signature with SHA-256 hash by using this key.
			 *
			 * \param	hash   	The hash.
			 * \param	sign   	The signature.
			 * \param	signLen	Length of the sign.
			 *
			 * \return	True if it succeeds, false if it fails.
			 */
			virtual bool VerifySignSha256(const General256Hash& hash, const void* sign, const size_t signLen) const;

			/**
			 * \brief	Verify signature with SHA-256 hash by using this key.
			 *
			 * \tparam	Container	Type of the container.
			 * \param	hash	The hash.
			 * \param	sign	The signature.
			 *
			 * \return	True if it succeeds, false if it fails.
			 */
			template<typename Container>
			bool VerifySignSha256(const General256Hash& hash, const Container& sign) const
			{
				return VerifySignSha256(hash, sign.data(), sign.size());
			}

			virtual std::string ToPubPemString() const;

			virtual bool ToPubDerArray(std::vector<uint8_t>& outArray) const;

		protected:
			PKey();

			PKey(mbedtls_pk_context* ptr, FreeFuncType freeFunc) noexcept :
				ObjBase(ptr, freeFunc)
			{}

			virtual std::string ToPubPemString(const size_t maxBufSize) const;

			virtual bool ToPubDerArray(std::vector<uint8_t>& outArray, const size_t maxBufSize) const;
		};

		class ECKeyPublic : public PKey
		{
		public:
			static ECKeyPublic Empty() { return ECKeyPublic(nullptr, &ObjBase::DoNotFree); }
			static ECKeyPublic FromPemString(const std::string & pemStr);
			static ECKeyPublic FromGeneral(const general_secp256r1_public_t & pub);

		public:
			/**
			* \brief	Constructor that accept a reference to mbedtls_pk_context object, thus, this instance doesn't
			* 			has the ownership.
			*
			* \param [in,out]	ref	The reference.
			*/
			ECKeyPublic(mbedtls_pk_context& ref) noexcept :
				PKey(ref)
			{}

			ECKeyPublic(ECKeyPublic&& other) noexcept :
				PKey(std::forward<PKey>(other))
			{}

			virtual ~ECKeyPublic() {}

			virtual ECKeyPublic& operator=(ECKeyPublic&& other) noexcept
			{
				ObjBase::operator=(std::forward<ObjBase>(other));
				return *this;
			}

			virtual operator bool() const noexcept override;

			bool ToGeneralPubKey(general_secp256r1_public_t& outKey) const;
			std::unique_ptr<general_secp256r1_public_t> ToGeneralPubKey() const;
			general_secp256r1_public_t ToGeneralPubKeyChecked() const;

			bool VerifySign(const general_secp256r1_signature_t& inSign, const uint8_t* hash, const size_t hashLen) const;

			template<size_t hashSize>
			bool VerifySign(const general_secp256r1_signature_t& inSign, const std::array<uint8_t, hashSize>& hash) const
			{
				return VerifySign(inSign, hash.data(), hash.size());
			}

			virtual std::string ToPubPemString() const override;
			virtual bool ToPubDerArray(std::vector<uint8_t>& outArray) const override;

			mbedtls_ecp_keypair* GetEcKeyPtr();

			const mbedtls_ecp_keypair* GetEcKeyPtr() const;

		protected:
			static ECKeyPublic FromPemDer(const void* ptr, size_t size);

			ECKeyPublic() :
				PKey()
			{}

			ECKeyPublic(mbedtls_pk_context* ptr, FreeFuncType freeFunc) noexcept :
				PKey(ptr, freeFunc)
			{}

		};

		class ECKeyPair : public ECKeyPublic
		{
		public:
			static ECKeyPair FromPemString(const std::string & pemStr);
			static ECKeyPair FromGeneral(const general_secp256r1_private_t & prv)
			{
				return FromGeneral(prv, nullptr);
			}

			static ECKeyPair FromGeneral(const general_secp256r1_private_t & prv, const general_secp256r1_public_t& pub)
			{
				return FromGeneral(prv, &pub);
			}

			static ECKeyPair GenerateNewKey();

		public:
			ECKeyPair(ECKeyPair&& other) noexcept :
				ECKeyPublic(std::forward<ECKeyPublic>(other))
			{}

			virtual ~ECKeyPair() {}

			virtual ECKeyPair& operator=(ECKeyPair&& other) noexcept
			{
				ObjBase::operator=(std::forward<ObjBase>(other));
				return *this;
			}

			bool ToGeneralPrvKey(PrivateKeyWrap& outKey) const;
			std::unique_ptr<PrivateKeyWrap> ToGeneralPrvKey() const;
			PrivateKeyWrap ToGeneralPrvKeyChecked() const;

			bool GenerateSharedKey(G256BitSecretKeyWrap& outKey, const ECKeyPublic& peerPubKey);
			bool EcdsaSign(general_secp256r1_signature_t& outSign, const uint8_t* hash, const size_t hashLen, const mbedtls_md_info_t* mdInfo) const;

			template<size_t hashSize>
			bool EcdsaSign(general_secp256r1_signature_t& outSign, const std::array<uint8_t, hashSize>& hash, const mbedtls_md_info_t* mdInfo) const
			{
				return EcdsaSign(outSign, hash.data(), hash.size(), mdInfo);
			}

			std::string ToPrvPemString() const;
			bool ToPrvDerArray(std::vector<uint8_t>& outArray) const;

		protected:
			static ECKeyPair FromGeneral(const general_secp256r1_private_t & prv, const general_secp256r1_public_t* pubPtr);
			static ECKeyPair FromPemDer(const void* ptr, size_t size);

			ECKeyPair() :
				ECKeyPublic()
			{}

			ECKeyPair(mbedtls_pk_context* ptr, FreeFuncType freeFunc) noexcept :
				ECKeyPublic(ptr, freeFunc)
			{}
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
			static X509Req FromPem(const std::string & pemStr);

		public:
			X509Req(const std::string& pemStr);
			X509Req(const PKey& keyPair, const std::string& commonName);

			X509Req(X509Req&& other) : 
				ObjBase(std::forward<ObjBase>(other)),
				m_pubKey(std::move(other.m_pubKey))
			{}

			X509Req(const X509Req& other) = delete;

			virtual ~X509Req() {}

			virtual X509Req& operator=(const X509Req& other) = delete;

			virtual X509Req& operator=(X509Req&& other) noexcept
			{
				ObjBase::operator=(std::forward<ObjBase>(other));
				if (this != &other)
				{
					m_pubKey = std::move(other.m_pubKey);
				}
				return *this;
			}

			virtual operator bool() const noexcept override;

			bool VerifySignature() const;
			const PKey& GetPublicKey() const;

			std::string ToPemString() const;

		protected:
			static X509Req FromPemDer(const void* ptr, size_t size);

			X509Req();

			X509Req(mbedtls_x509_csr* ptr, FreeFuncType freeFunc);

		private:
			PKey m_pubKey;
		};

		class X509Crl : public ObjBase<mbedtls_x509_crl>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_x509_crl* ptr);

			static X509Crl FromPem(const std::string & pemStr);

		public:
			X509Crl(const std::string& pemStr) :
				X509Crl(FromPem(pemStr))
			{}

			X509Crl(X509Crl&& other) noexcept :
				ObjBase(std::forward<ObjBase>(other))
			{}

			X509Crl(const X509Crl& other) = delete;

			virtual ~X509Crl() {}


			std::string ToPemString() const;
		
		protected:
			static X509Crl FromPemDer(const void* ptr, size_t size);

			X509Crl();

			X509Crl(mbedtls_x509_crl* ptr, FreeFuncType freeFunc) :
				ObjBase(ptr, freeFunc)
			{}

		};

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

			X509Cert(const X509Cert& caCert, const PKey& prvKey, const PKey& pubKey,
				const BigNumber& serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
				const std::string& x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap);

			X509Cert(const PKey& prvKey,
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
			bool VerifySignature(const PKey& pubKey) const;

			bool Verify(const X509Cert& trustedCa, mbedtls_x509_crl* caCrl, const char* commonName,
				int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void* vrfyParam) const;
			bool Verify(const X509Cert& trustedCa, mbedtls_x509_crl* caCrl, const char* commonName, const mbedtls_x509_crt_profile& profile,
				int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void* vrfyParam) const;

			const PKey& GetPublicKey() const;
			std::string ToPemString() const;

			std::string GetCommonName() const;

			bool NextCert();
			bool PreviousCert();
			void SwitchToFirstCert();

		protected:
			static X509Cert FromPemDer(const void* ptr, size_t size);

			X509Cert(mbedtls_x509_crt* ptr, FreeFuncType freeFunc);

		private:
			PKey m_pubKey;
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
