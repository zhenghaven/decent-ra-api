#pragma once

#include <cstdint>

#include <string>
#include <vector>
#include <map>

#include "GeneralKeyTypes.h"

typedef struct mbedtls_mpi mbedtls_mpi;
typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_ecp_keypair mbedtls_ecp_keypair;
typedef struct mbedtls_x509_crt mbedtls_x509_crt;
typedef struct mbedtls_x509_csr mbedtls_x509_csr;

namespace MbedTlsObj
{
	template<typename T>
	class ObjBase
	{
	public:
		ObjBase(T* ptr) :
			m_ptr(ptr)
		{}

		ObjBase(const ObjBase& other) = delete;
		ObjBase(ObjBase&& other)
		{
			this->m_ptr = other.m_ptr;
			other.m_ptr = nullptr;
		}

		virtual ObjBase& operator=(const ObjBase& other) = delete;
		virtual ObjBase& operator=(ObjBase&& other)
		{
			if (this != &other)
			{
				this->m_ptr = other.m_ptr;
				other.m_ptr = nullptr;
			}
			return *this;
		}

		virtual ~ObjBase() {}

		virtual operator bool() const
		{
			return m_ptr;
		}

		T* GetInternalPtr() const
		{
			return m_ptr;
		}

		T* Release()
		{
			T* tmp = m_ptr;
			m_ptr = nullptr;
			return tmp;
		}

	protected:
		T * m_ptr;
	};

	class BigNumber : public ObjBase<mbedtls_mpi>
	{
	public:
		static BigNumber GenRandomNumber(size_t size);

	public:
		BigNumber() = delete;
		BigNumber(BigNumber&& other);
		BigNumber(mbedtls_mpi* ptr);
		~BigNumber();

	private:
	};

	class ECKeyPublic : public ObjBase<mbedtls_pk_context>
	{
	public:
		ECKeyPublic() = delete;
		ECKeyPublic(mbedtls_pk_context* ptr, bool isOwner);
		ECKeyPublic(const general_secp256r1_public_t& pub);
		ECKeyPublic(const std::string& pemStr);
		ECKeyPublic(ECKeyPublic&& other);
		virtual ~ECKeyPublic();

		virtual ECKeyPublic& operator=(ECKeyPublic&& other);

		bool ToGeneralPublicKey(general_secp256r1_public_t& outKey) const;

		std::string ToPubPemString() const;
		bool ToPubDerArray(std::vector<uint8_t>& outArray) const;

		mbedtls_ecp_keypair* GetInternalECKey() const;

	private:
		bool m_isOwner;

	};

	class ECKeyPair : public ECKeyPublic
	{
	public:
		//Dummy struct to indicate the need for generating a new key pair.
		struct GeneratePair
		{
			explicit GeneratePair() = default;
		};

		static constexpr GeneratePair generatePair{};

	public:
		ECKeyPair() = delete;
		ECKeyPair(mbedtls_pk_context* ptr, bool isOwner);
		ECKeyPair(GeneratePair);
		ECKeyPair(const general_secp256r1_private_t& prv);
		ECKeyPair(const general_secp256r1_private_t& prv, const general_secp256r1_public_t& pub);
		ECKeyPair(const std::string& pemStr);
		virtual ~ECKeyPair();

		bool ToGeneralPrivateKey(general_secp256r1_private_t& outKey) const;

		std::string ToPrvPemString() const;
		bool ToPrvDerArray(std::vector<uint8_t>& outArray) const;

	};

	class X509Req : public ObjBase<mbedtls_x509_csr>
	{
	public:
		X509Req() = delete;
		X509Req(const std::string& pemStr);
		X509Req(mbedtls_x509_csr* ptr, const std::string& pemStr);
		X509Req(const ECKeyPair& keyPair, const std::string& commonName);
		~X509Req();

		bool VerifySignature() const;
		const ECKeyPublic& GetPublicKey() const;

		std::string ToPemString() const;
		//bool ToDerArray(std::vector<uint8_t>& outArray) const;

	private:
		std::string m_pemStr;
		ECKeyPublic m_pubKey;
	};

	class X509Cert : public ObjBase<mbedtls_x509_crt>
	{
	public:
		X509Cert() = delete;
		X509Cert(const std::string& pemStr);
		X509Cert(mbedtls_x509_crt* ptr, const std::string& pemStr);
		X509Cert(const X509Cert& caCert, const MbedTlsObj::ECKeyPair& prvKey, const MbedTlsObj::ECKeyPublic& pubKey,
			const BigNumber& serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
			const std::string& x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap);

		X509Cert(const MbedTlsObj::ECKeyPair& prvKey, 
			const BigNumber& serialNum, int64_t validTime, bool isCa, int maxChainDepth, unsigned int keyUsage, unsigned char nsType,
			const std::string& x509NameList, const std::map<std::string, std::pair<bool, std::string> >& extMap);
		~X509Cert();

		bool GetExtensions(std::map<std::string, std::pair<bool, std::string> >& extMap) const;
		bool VerifySignature() const;
		bool VerifySignature(const ECKeyPublic& pubKey) const;

		const ECKeyPublic& GetPublicKey() const;
		const std::string& ToPemString() const;

	private:
		std::string m_pemStr;
		ECKeyPublic m_pubKey;
	};

}
