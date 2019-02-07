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
	namespace MbedTlsHelper
	{
		class Drbg;
	}

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

		protected:
			void SetPtr(T* ptr) noexcept
			{
				m_ptr = ptr;
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
			{}

			/**
			 * \brief	Constructor that accept a reference to mbedtls_mpi object, thus, this instance doesn't
			 * 			has the ownership.
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
			 * \brief	Constructor that accept a pointer to mbedtls_mpi object, thus, this class doesn't has
			 * 			the owner ship.
			 *
			 * \param [in,out]	ptr			If non-null, the pointer.
			 * \param 		  	freeFunc	The free function.
			 */
			BigNumber(mbedtls_mpi* ptr, FreeFuncType freeFunc) :
				ObjBase(ptr, freeFunc)
			{}

		};

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
			virtual PKey& operator=(PKey&& other) noexcept
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

		protected:
			PKey();

			PKey(mbedtls_pk_context* ptr, FreeFuncType freeFunc) noexcept :
				ObjBase(ptr, freeFunc)
			{}
		};

		class Gcm : public ObjBase<mbedtls_gcm_context>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_gcm_context* ptr);

			static Gcm Empty() { return Gcm(nullptr, &ObjBase::DoNotFree); }

		public:
			/**
			* \brief	Constructor that accept a reference to mbedtls_gcm_context object, thus, this instance doesn't
			* 			has the ownership.
			*
			* \param [in,out]	ref	The reference.
			*/
			Gcm(mbedtls_gcm_context& ref) noexcept :
				ObjBase(&ref, &ObjBase::DoNotFree)
			{}

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	other	The other.
			 */
			Gcm(Gcm&& other) noexcept :
				ObjBase(std::forward<ObjBase>(other))
			{}

			/** \brief	Destructor */
			virtual ~Gcm() {}

			virtual Gcm& operator=(Gcm&& other) noexcept
			{
				ObjBase::operator=(std::forward<ObjBase>(other));
				return *this;
			}

			template<typename DataCtar, typename AddCtar, typename IvStru, typename TagStru>
			bool EncryptStruct(const DataCtar& inData, void* outData, const size_t outLen,
				const IvStru& iv, const AddCtar& add, TagStru& outTag)
			{
				return inData.size() <= outLen && Encrypt(inData.data(), outData, inData.size(), 
					&iv, sizeof(iv), add.data(), add.size(), 
					&outTag, sizeof(outTag));
			}

			template<typename DataCtar, typename IvStru, typename TagStru>
			bool EncryptStruct(const DataCtar& inData, void* outData, const size_t outLen,
				const IvStru& iv, TagStru& outTag)
			{
				return inData.size() <= outLen && Encrypt(inData.data(), outData, inData.size(),
					&iv, sizeof(iv), nullptr, 0, 
					&outTag, sizeof(outTag));
			}

			template<typename DataCtar, typename AddCtar, typename IvStru, typename TagStru>
			bool DecryptStruct(const void* inData, DataCtar& outData, const size_t inLen,
				const IvStru& iv, const AddCtar& add, const TagStru& outTag)
			{
				return outData && outData.size() >= inLen && Decrypt(inData, &outData[0], inLen,
					&iv, sizeof(iv), add.data(), add.size(),
					&outTag, sizeof(outTag));
			}

			template<typename DataCtar, typename IvStru, typename TagStru>
			bool DecryptStruct(const void* inData, DataCtar& outData, const size_t inLen,
				const IvStru& iv, const TagStru& outTag)
			{
				return inData && outData.size() >= inLen && Decrypt(inData, &outData[0], inLen,
					&iv, sizeof(iv), nullptr, 0,
					&outTag, sizeof(outTag));
			}
		
		protected:
			Gcm();

			Gcm(mbedtls_gcm_context* ptr, FreeFuncType freeFunc) noexcept :
				ObjBase(ptr, freeFunc)
			{}

			/**
			* \brief	Encrypts data with AES-GCM.
			*
			* \param 		  	inData 	Input data to be encrypted.
			* \param [out]		outData	Output encrypted data.
			* \param 		  	dataLen	Length of the data.
			* \param 		  	iv	   	The iv.
			* \param 		  	ivLen  	Length of the iv.
			* \param 		  	add	   	The additional authentication info.
			* \param 		  	addLen 	Length of the add.
			* \param [out]		tag	   	Output tag.
			* \param 		  	tagLen 	Length of the tag.
			*
			* \return	True if it succeeds, false if it fails.
			*/
			virtual bool Encrypt(const void* inData, void* outData, const size_t dataLen,
				const void* iv, const size_t ivLen, const void* add, const size_t addLen,
				void* tag, const size_t tagLen);

			virtual bool Decrypt(const void* inData, void* outData, const size_t dataLen,
				const void* iv, const size_t ivLen, const void* add, const size_t addLen,
				const void* tag, const size_t tagLen);
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

			std::string ToPubPemString() const;
			bool ToPubDerArray(std::vector<uint8_t>& outArray) const;

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

			bool GenerateSharedKey(General256BitKey& outKey, const ECKeyPublic& peerPubKey);
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
					m_certStack = std::move(other.m_certStack);
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

			X509Cert();

			X509Cert(mbedtls_x509_crt* ptr, FreeFuncType freeFunc);

		private:
			PKey m_pubKey;
			std::vector<mbedtls_x509_crt*> m_certStack;
		};

		class Aes128Gcm : public Gcm
		{
		public:
			Aes128Gcm(const General128BitKey& key);
			Aes128Gcm(const uint8_t(&key)[GENERAL_128BIT_16BYTE_SIZE]);
			Aes128Gcm(Aes128Gcm&& other);
			virtual ~Aes128Gcm() {}

			virtual Aes128Gcm& operator=(const Aes128Gcm& other) = delete;
			virtual Aes128Gcm& operator=(Aes128Gcm&& other)
			{
				Gcm::operator=(std::forward<Gcm>(other));
				return *this;
			}

		protected:
			static Aes128Gcm ConstructGcmCtx(const void* key, const size_t size);

			Aes128Gcm() :
				Gcm()
			{}
		};

		class TlsConfig : public ObjBase<mbedtls_ssl_config>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_ssl_config* ptr);

		public:
			TlsConfig(TlsConfig&& other);

			TlsConfig(const TlsConfig& other) = delete;

			virtual ~TlsConfig();

			virtual TlsConfig& operator=(const TlsConfig& other) = delete;

			virtual TlsConfig& operator=(TlsConfig&& other) noexcept;

			virtual operator bool() const noexcept override;

		protected:
			TlsConfig();

			TlsConfig(mbedtls_ssl_config* ptr, FreeFuncType freeFunc);

		private:
			std::unique_ptr<Decent::MbedTlsHelper::Drbg> m_rng;
		};

	}
}
