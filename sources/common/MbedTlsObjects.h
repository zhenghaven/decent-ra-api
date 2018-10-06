#pragma once

#include <cstdint>

#include <string>
#include <vector>

#include "GeneralKeyTypes.h"

typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_ecp_keypair mbedtls_ecp_keypair;

template<typename T>
class MbedTlsObjBase
{
public:
	MbedTlsObjBase(T* ptr) :
		m_ptr(ptr)
	{}

	MbedTlsObjBase(const MbedTlsObjBase& other) = delete;
	MbedTlsObjBase(MbedTlsObjBase&& other)
	{
		this->m_ptr = other.m_ptr;
		other.m_ptr = nullptr;
	}

	virtual MbedTlsObjBase& operator=(const MbedTlsObjBase& other) = delete;
	virtual MbedTlsObjBase& operator=(MbedTlsObjBase&& other)
	{
		if (this != &other)
		{
			this->m_ptr = other.m_ptr;
			other.m_ptr = nullptr;
		}
		return *this;
	}

	virtual ~MbedTlsObjBase() {}

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

class MbedECKeyPublic : public MbedTlsObjBase<mbedtls_pk_context>
{
public:
	MbedECKeyPublic() = delete;
	MbedECKeyPublic(mbedtls_pk_context* m_ptr, bool isOwner);
	MbedECKeyPublic(const general_secp256r1_public_t& pub);
	MbedECKeyPublic(const std::string& pemStr);
	MbedECKeyPublic(MbedECKeyPublic&& other);
	virtual ~MbedECKeyPublic();

	virtual MbedECKeyPublic& operator=(MbedECKeyPublic&& other);

	std::string ToPubPemString() const;
	bool ToPubDerArray(std::vector<uint8_t>& outArray) const;

	mbedtls_ecp_keypair* GetInternalECKey() const;

private:
	bool m_isOwner;

};

class MbedECKeyPair : public MbedECKeyPublic
{
public:
	MbedECKeyPair() = delete;
	MbedECKeyPair(mbedtls_pk_context* m_ptr, bool isOwner);
	MbedECKeyPair(const general_secp256r1_private_t& prv);
	MbedECKeyPair(const general_secp256r1_private_t& prv, const general_secp256r1_public_t& pub);
	MbedECKeyPair(const std::string& pemStr);
	virtual ~MbedECKeyPair();

	std::string ToPrvPemString() const;
	bool ToPrvDerArray(std::vector<uint8_t>& outArray) const;

};
