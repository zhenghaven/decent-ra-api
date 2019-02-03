#pragma once

#include <cstdint>

#include <string>
#include <vector>
#include <memory>
#include <map>

#include "../GeneralKeyTypes.h"

typedef struct mbedtls_mpi mbedtls_mpi;
typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_ecp_keypair mbedtls_ecp_keypair;
typedef struct mbedtls_gcm_context mbedtls_gcm_context;
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_x509_csr mbedtls_x509_csr;
typedef struct mbedtls_x509_crl mbedtls_x509_crl;
typedef struct mbedtls_x509_crt_profile mbedtls_x509_crt_profile;
typedef struct mbedtls_ssl_config mbedtls_ssl_config;
typedef struct mbedtls_md_info_t mbedtls_md_info_t;

namespace Decent
{
	namespace MbedTlsObj
	{
		
		/** \brief	Dummy struct to indicate the need for generating a new big number. Similar way can be found in std::unique_lock. */
		struct Generate
		{
			explicit Generate() = default;
		};
		constexpr Generate gen;

		/** \brief	An object base class for MbedTLS objects. */
		template<typename T>
		class ObjBase
		{
		public:
			/** \brief	Defines an alias representing the type of free function for m_ptr. */
			typedef void(*FreeFuncType)(T*);

			/**
			 * \brief	An empty function which don't free the m_ptr.
			 * 			This is necessary when this instance is not the real owner of 
			 * 			the MbedTLS object that this instance is holding.
			 *
			 * \param [in,out]	ptr	If non-null, the pointer.
			 */
			static void DoNotFree(T* ptr) noexcept { /*Do nothing.*/ }

		public:
			ObjBase() = delete;

			/**
			 * \brief	Constructor
			 * 			Usually this class is used internally, thus, it's the developer's responsibility to 
			 * 			make sure the value passed in is correct (e.g. not null).
			 *
			 * \param [in,out]	ptr			If non-null, the pointer to the MbedTLS object.
			 * \param 		  	freeFunc	The free function to free the MbedTLS object *AND delete the pointer*.
			 */
			ObjBase(T* ptr, FreeFuncType freeFunc) noexcept :
				m_ptr(ptr),
				m_freeFunc(freeFunc)
			{}

			ObjBase(const ObjBase& other) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	other	The other instance.
			 */
			ObjBase(ObjBase&& other) noexcept :
				m_ptr(other.m_ptr),
				m_freeFunc(other.m_freeFunc)
			{
				other.m_ptr = nullptr;
				other.m_freeFunc = &DoNotFree;
			}

			virtual ObjBase& operator=(const ObjBase& other) = delete;

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	other	The other instance.
			 *
			 * \return	A reference to this object.
			 */
			virtual ObjBase& operator=(ObjBase&& other) noexcept
			{
				if (this != &other)
				{
					this->m_ptr = other.m_ptr;
					this->m_freeFunc = other.m_freeFunc;

					other.m_ptr = nullptr;
					other.m_freeFunc = &DoNotFree;
				}
				return *this;
			}

			/** \brief	Destructor */
			virtual ~ObjBase() 
			{
				(*m_freeFunc)(m_ptr);
				m_ptr = nullptr;
			}

			/**
			 * \brief	Cast that converts this instance to a bool
			 * 			This function basically check whether or not the pointer m_ptr is null.
			 *
			 * \return	True if m_ptr is not null, otherwise, false.
			 */
			virtual operator bool() const noexcept
			{
				return m_ptr != nullptr;
			}

			/**
			 * \brief	Gets the pointer to the MbedTLS object.
			 *
			 * \return	The pointer to the MbedTLS object.
			 */
			T* Get() const noexcept
			{
				return m_ptr;
			}

			/**
			 * \brief	Releases the ownership of the MbedTLS Object, and 
			 * 			return the pointer to the MbedTLS object.
			 *
			 * \return	The pointer to the MbedTLS object.
			 */
			T* Release() noexcept
			{
				T* tmp = m_ptr;

				m_ptr = nullptr;
				m_freeFunc = &DoNotFree;

				return tmp;
			}

			/**
			 * \brief	Query if this is the actual owner of MbedTLS object.
			 *
			 * \return	True if it's, false if not.
			 */
			virtual bool IsOwner() const noexcept
			{
				return m_freeFunc == &DoNotFree;
			}

		private:
			T * m_ptr;
			FreeFuncType m_freeFunc;
		};

		class BigNumber : public ObjBase<mbedtls_mpi>
		{
		public:

			/**
			 * \brief	Function that frees MbedTLS object and delete the pointer.
			 *
			 * \param [in,out]	ptr	If non-null, the pointer.
			 */
			static void FreeObject(mbedtls_mpi* ptr);

			/**
			 * \brief	Generates a random number with specific size.
			 *
			 * \param	size	The size.
			 *
			 * \return	The random number.
			 */
			static BigNumber GenRandomNumber(size_t size);

			/**
			 * \brief	Construct a big number from binary in little-endian.
			 *
			 * \param	in  	The pointer to the start address.
			 * \param	size	The size.
			 *
			 * \return	The BigNumber.
			 */
			static BigNumber FromLittleEndian(const void* in, const size_t size);

			/**
			 * \brief	Construct a big number from binary in little-endian.
			 *
			 * \param	in	The object with size (e.g. an instance of a struct).
			 *
			 * \return	The BigNumber.
			 */
			template<typename T>
			static BigNumber FromLittleEndian(const T& in)
			{
				return FromLittleEndian(&in, sizeof(T));
			}

		public:
			BigNumber() = delete;

			/**
			 * \brief	Constructor that generate a big number. Nothing has been filled-in.
			 *
			 * \param	parameter1	The dummy variable that indicates the need for generating a big number object.
			 */
			BigNumber(const Generate&);

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	other	The other instance.
			 */
			BigNumber(BigNumber&& other) noexcept : 
				ObjBase(std::forward<ObjBase>(other))
			{
			}

			/**
			 * \brief	Constructor that accept a reference to mbedtls_mpi object, thus, this class doesn't
			 * 			has the owner ship.
			 *
			 * \param [in,out]	ref to mbedtls_mpi object.
			 */
			BigNumber(mbedtls_mpi& ref) :
				ObjBase(&ref, &ObjBase::DoNotFree)
			{}

			BigNumber(const BigNumber& other) = delete;

			/** \brief	Destructor */
			virtual ~BigNumber() noexcept {}

			/**
			 * \brief	Gets the size of this big number.
			 *
			 * \return	The size.
			 */
			size_t GetSize() const;

			/**
			 * \brief	Converts this big number to a little endian binary
			 *
			 * \param [in,out]	out 	If non-null, the output address.
			 * \param 		  	size	The size of the output space. It must be exactly same as the size 
			 * 							of this big number.
			 *
			 * \return	Whether or not the conversion is successful.
			 */
			bool ToLittleEndian(void* out, const size_t size);

			/**
			* \brief	Converts this big number to a little endian binary
			*
			* \param [in,out]	out 	The reference to the output space. The size must be exactly same as 
			* 							the size of this big number.
			*
			* \return	Whether or not the conversion is successful.
			*/
			template<typename T>
			bool ToLittleEndian(T& out)
			{
				return ToLittleEndian(&out, sizeof(T));
			}

		private:
			/**
			* \brief	Constructor that accept a pointer to mbedtls_mpi object, thus, this class doesn't has the owner ship.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			BigNumber(mbedtls_mpi* ptr) :
				ObjBase(ptr, &ObjBase::DoNotFree)
			{}

		};

		class PKey : public ObjBase<mbedtls_pk_context>
		{
		public:
			PKey(mbedtls_pk_context* ptr, bool isOwner);
			PKey(PKey&& other);
			virtual ~PKey();

			virtual void Destroy() override;
			virtual PKey& operator=(const PKey& other) = delete;
			virtual PKey& operator=(PKey&& other);

			virtual bool VerifySignatureSha256(const General256Hash& hash, const std::vector<uint8_t>& signature) const;

		private:
			bool m_isOwner;
		};

		class Gcm : public ObjBase<mbedtls_gcm_context>
		{
		public:
			Gcm(mbedtls_gcm_context* ptr);
			Gcm(Gcm&& other);
			virtual ~Gcm();

			virtual void Destroy() override;
			virtual Gcm& operator=(const Gcm& other) = delete;
			virtual Gcm& operator=(Gcm&& other);

			virtual bool Encrypt(const uint8_t* inData, uint8_t* outData, const size_t dataLen,
				const uint8_t* iv, const size_t ivLen, const uint8_t* add, const size_t addLen,
				uint8_t* tag, const size_t tagLen);

			virtual bool Decrypt(const uint8_t* inData, uint8_t* outData, const size_t dataLen,
				const uint8_t* iv, const size_t ivLen, const uint8_t* add, const size_t addLen,
				const uint8_t* tag, const size_t tagLen);

			//Not very useful now.
			//template<typename Container>
			//bool Encrypt(const Container& inData, uint8_t* outData, const size_t outLen,
			//	const uint8_t* iv, const size_t ivLen, const uint8_t* add, const size_t addLen, General128Tag& outTag)
			//{
			//	return inData.size() > 0 && (inData.size() * sizeof(inData[0])) == outLen &&
			//		Encrypt(reinterpret_cast<const uint8_t*>(inData.data()), outData, outLen, iv, ivLen, add, addLen, outTag);
			//}
			//template<typename Container>
			//bool Encrypt(const uint8_t* inData, Container& outData, const size_t inLen,
			//	const uint8_t* iv, const size_t ivLen, const uint8_t* add, const size_t addLen, General128Tag& outTag)
			//{
			//	return outData.size() > 0 && (outData.size() * sizeof(outData[0])) == inLen &&
			//		Encrypt(inData, reinterpret_cast<const uint8_t*>(&outData[0]), inLen, iv, ivLen, add, addLen, outTag);
			//}
			//template<typename inDataContainer, typename outDataContainer>
			//bool Encrypt(const inDataContainer& inData, outDataContainer& outData,
			//	const uint8_t* iv, const size_t ivLen, const uint8_t* add, const size_t addLen, General128Tag& outTag)
			//{
			//	const size_t inLen = 0;
			//	return inData.size() > 0 && outData.size() > 0 && 
			//		(inLen = inData.size() * sizeof(inData[0])) == (outData.size() * sizeof(outData[0])) &&
			//		Encrypt(reinterpret_cast<const uint8_t*>(inData.data()), 
			//			reinterpret_cast<const uint8_t*>(&outData[0]), inLen, iv, ivLen, add, addLen, outTag);
			//}
		};

		class ECKeyPublic : public PKey
		{
		public:
			ECKeyPublic() = delete;
			ECKeyPublic(mbedtls_pk_context * ptr, bool isOwner);
			ECKeyPublic(const general_secp256r1_public_t& pub);
			ECKeyPublic(const std::string& pemStr);
			ECKeyPublic(ECKeyPublic&& other);
			virtual ~ECKeyPublic() {}

			virtual ECKeyPublic& operator=(const ECKeyPublic& other) = delete;
			virtual ECKeyPublic& operator=(ECKeyPublic&& other);
			virtual operator bool() const override;

			bool ToGeneralPubKey(general_secp256r1_public_t& outKey) const;
			std::unique_ptr<general_secp256r1_public_t> ToGeneralPubKey() const;
			general_secp256r1_public_t ToGeneralPubKeyChecked() const;

			bool VerifySign(const general_secp256r1_signature_t& inSign, const uint8_t* hash, const size_t hashLen) const;

			template<size_t hashSize>
			bool VerifySign(const general_secp256r1_signature_t& inSign, const std::array<uint8_t, hashSize>& hash) const
			{
				return VerifySign(inSign, hash.data(), hash.size());
			}

			std::string ToPubPemString() const;
			bool ToPubDerArray(std::vector<uint8_t>& outArray) const;

			mbedtls_ecp_keypair* GetInternalECKey() const;
		};

		class ECKeyPair : public ECKeyPublic
		{
		public:

		public:
			ECKeyPair() = delete;
			ECKeyPair(mbedtls_pk_context* ptr, bool isOwner);
			ECKeyPair(const Generate&);
			ECKeyPair(const general_secp256r1_private_t& prv);
			ECKeyPair(const general_secp256r1_private_t& prv, const general_secp256r1_public_t& pub);
			ECKeyPair(const std::string& pemStr);
			ECKeyPair(ECKeyPair&& other);
			virtual ~ECKeyPair() {}

			//bool ToGeneralPrivateKey(PrivateKeyWrap& outKey) const;
			//PrivateKeyWrap* ToGeneralPrivateKeyWrap() const;

			bool ToGeneralPrvKey(PrivateKeyWrap& outKey) const;
			std::unique_ptr<PrivateKeyWrap> ToGeneralPrvKey() const;
			PrivateKeyWrap ToGeneralPrvKeyChecked() const;

			bool GenerateSharedKey(General256BitKey& outKey, const ECKeyPublic& peerPubKey);
			bool EcdsaSign(general_secp256r1_signature_t& outSign, const uint8_t* hash, const size_t hashLen, const mbedtls_md_info_t* mdInfo) const;

			template<size_t hashSize>
			bool EcdsaSign(general_secp256r1_signature_t& outSign, const std::array<uint8_t, hashSize>& hash, const mbedtls_md_info_t* mdInfo) const
			{
				return EcdsaSign(outSign, hash.data(), hash.size(), mdInfo);
			}

			std::string ToPrvPemString() const;
			bool ToPrvDerArray(std::vector<uint8_t>& outArray) const;

			//private:
			//	bool ToGeneralPrivateKey(general_secp256r1_private_t& outKey) const;
			//	general_secp256r1_private_t* ToGeneralPrivateKey() const;
		};

		class X509Req : public ObjBase<mbedtls_x509_csr>
		{
		public:
			X509Req() = delete;
			X509Req(const std::string& pemStr);
			X509Req(mbedtls_x509_csr* ptr, const std::string& pemStr);
			X509Req(const PKey& keyPair, const std::string& commonName);
			X509Req(const X509Req& other) = delete;
			virtual ~X509Req();

			virtual X509Req& operator=(const X509Req& other) = delete;
			virtual X509Req& operator=(X509Req&& other);
			virtual void Destroy() override;
			virtual operator bool() const override;

			bool VerifySignature() const;
			const PKey& GetPublicKey() const;

			std::string ToPemString() const;
			//bool ToDerArray(std::vector<uint8_t>& outArray) const;

		private:
			std::string m_pemStr;
			PKey m_pubKey;
		};

		class X509Crl : public ObjBase<mbedtls_x509_crl>
		{
		public:
			X509Crl() = delete;
			X509Crl(const std::string& pemStr);
			X509Crl(mbedtls_x509_crl* ptr, const std::string& pemStr);
			X509Crl(const X509Crl& other) = delete;
			virtual ~X509Crl();

			virtual void Destroy() override;

			std::string ToPemString() const;
			//bool ToDerArray(std::vector<uint8_t>& outArray) const;

		private:
			std::string m_pemStr;
		};

		class X509Cert : public ObjBase<mbedtls_x509_crt>
		{
		public:
			X509Cert() = delete;
			X509Cert(const std::string& pemStr);
			X509Cert(mbedtls_x509_crt* ptr, const std::string& pemStr);
			X509Cert(mbedtls_x509_crt* ptr);
			X509Cert(const X509Cert& caCert, const PKey& prvKey, const PKey& pubKey,
				const BigNumber& serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
				const std::string& x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap);

			X509Cert(const PKey& prvKey,
				const BigNumber& serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
				const std::string& x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap);
			X509Cert(const X509Cert& other) = delete;
			virtual ~X509Cert();

			virtual X509Cert& operator=(const X509Cert& other) = delete;
			virtual X509Cert& operator=(X509Cert&& other);
			virtual void Destroy() override;
			virtual operator bool() const override;

			bool GetExtensions(std::map<std::string, std::pair<bool, std::string> >& extMap) const;
			bool VerifySignature() const;
			bool VerifySignature(const PKey& pubKey) const;

			bool Verify(const X509Cert& trustedCa, mbedtls_x509_crl* caCrl, const char* commonName,
				int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void* vrfyParam) const;
			bool Verify(const X509Cert& trustedCa, mbedtls_x509_crl* caCrl, const char* commonName, const mbedtls_x509_crt_profile& profile,
				int(*vrfyFunc)(void *, mbedtls_x509_crt *, int, uint32_t *), void* vrfyParam) const;

			const PKey& GetPublicKey() const;
			const std::string& ToPemString() const;

			const std::string& GetCommonName() const { return m_commonName; }

			bool NextCert();
			bool PreviousCert();
			void SwitchToFirstCert();

		private:
			bool m_isOwner;
			std::string m_pemStr;
			PKey m_pubKey;
			std::string m_commonName;
			std::vector<mbedtls_x509_crt*> m_certStack;
		};

		class Aes128Gcm : public Gcm
		{
		public:
			Aes128Gcm() = delete;
			Aes128Gcm(const General128BitKey& key);
			Aes128Gcm(const uint8_t(&key)[GENERAL_128BIT_16BYTE_SIZE]);
			Aes128Gcm(Aes128Gcm&& other);
			virtual ~Aes128Gcm() {}

			virtual Aes128Gcm& operator=(const Aes128Gcm& other) = delete;
			virtual Aes128Gcm& operator=(Aes128Gcm&& other);

		};

		class TlsConfig : public ObjBase<mbedtls_ssl_config>
		{
		public:
			TlsConfig(mbedtls_ssl_config* ptr);
			TlsConfig(TlsConfig&& other);
			TlsConfig(const TlsConfig& other) = delete;
			virtual ~TlsConfig();

			virtual void Destroy() override;
			virtual TlsConfig& operator=(const TlsConfig& other) = delete;
			virtual TlsConfig& operator=(TlsConfig&& other);

			virtual void BasicInit();

		private:
			void* m_rng;
		};

	}
}
