#include "MbedTlsHelpers.h"

#include <cstring>
#include <cstdlib>

#include <mbedtls/asn1.h>
#include <mbedtls/md.h>
#include <mbedtls/cmac.h>

namespace
{
	static constexpr int MBEDTLS_SUCCESS_RET = 0;
}

bool MbedTlsHelper::MbedTlsAsn1DeepCopy(mbedtls_asn1_buf& dest, const mbedtls_asn1_buf& src)
{
	if (src.p == nullptr ||
		(dest.p = reinterpret_cast<uint8_t*>(malloc(src.len))) == nullptr)
	{
		return false;
	}

	dest.tag = src.tag;
	dest.len = src.len;
	
	std::memcpy(dest.p, src.p, dest.len);
	
	return true;
}

bool MbedTlsHelper::MbedTlsAsn1DeepCopy(mbedtls_asn1_named_data & dest, const mbedtls_asn1_named_data & src)
{
	const mbedtls_asn1_named_data* curSrc = &src;
	mbedtls_asn1_named_data* curDest = &dest;

	do
	{
		MbedTlsAsn1DeepCopy(curDest->oid, curSrc->oid);
		MbedTlsAsn1DeepCopy(curDest->val, curSrc->val);
		curDest->next_merged = curSrc->next_merged;

		curDest->next = (curSrc->next == nullptr) ?
			nullptr :
			reinterpret_cast<struct mbedtls_asn1_named_data *>(calloc(1, sizeof(struct mbedtls_asn1_named_data)));

		curSrc = curSrc->next;
		curDest = curDest->next;

	} while (curSrc != nullptr && curDest != nullptr);
	

	return (curSrc == nullptr && curDest == nullptr);
}

bool MbedTlsHelper::MbedTlsAsn1DeepCopy(mbedtls_asn1_named_data *& dest, const mbedtls_asn1_named_data & src)
{
	if (dest != nullptr)
	{
		mbedtls_asn1_free_named_data_list(&dest);
	}

	dest = reinterpret_cast<struct mbedtls_asn1_named_data *>(calloc(1, sizeof(struct mbedtls_asn1_named_data)));

	return MbedTlsAsn1DeepCopy(*dest, src);
}

bool MbedTlsHelper::CalcHashSha256(const std::string & data, General256Hash& hash)
{
	return mbedtls_md(mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256),
		reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash.data()) == MBEDTLS_SUCCESS_RET;
}

bool MbedTlsHelper::CalcCmacAes128(const General128BitKey & key, const uint8_t * data, size_t dataSize, General128Tag & outTag)
{
	if (!data || dataSize <= 0)
	{
		return false;
	}

	return mbedtls_cipher_cmac(mbedtls_cipher_info_from_type(mbedtls_cipher_type_t::MBEDTLS_CIPHER_AES_128_ECB),
		key.data(), key.size() * GENERAL_BITS_PER_BYTE,
		data, dataSize,
		outTag.data()) == MBEDTLS_SUCCESS_RET;
}

bool MbedTlsHelper::VerifyCmacAes128(const General128BitKey & key, const uint8_t * data, size_t dataSize, const General128Tag & inTag)
{
	if (!data || dataSize <= 0)
	{
		return false;
	}
	General128Tag tag;
	if (!CalcCmacAes128(key, data, dataSize, tag) ||
		!consttime_memequal(tag.data(), inTag.data(), tag.size()))
	{
		return false;
	}
	return true;
}

#define EC_DERIVATION_BUFFER_SIZE(label_length) ((label_length) +4)

bool MbedTlsHelper::CkdfAes128(const uint8_t * key, size_t keySize, const char * label, size_t labelLen, General128BitKey & outKey)
{
	size_t derivationBufferLength = EC_DERIVATION_BUFFER_SIZE(labelLen);
	if (!key || !label || keySize <= 0 || labelLen <= 0 ||
		labelLen > derivationBufferLength)
	{
		return false;
	}
	General128BitKey cmacKey;
	General128BitKey deriveKey;
	cmacKey.fill(0);

	if (!CalcCmacAes128(cmacKey, key, keySize, deriveKey))
	{
		deriveKey.fill(0);
		return false;
	}

	std::vector<uint8_t> derivationBuffer(derivationBufferLength, 0);

	derivationBuffer[0] = 0x01;
	memcpy(&derivationBuffer[1], label, labelLen);
	uint16_t *key_len = reinterpret_cast<uint16_t*>(&derivationBuffer[derivationBufferLength - 2]);
	*key_len = 0x0080;

	bool res = CalcCmacAes128(deriveKey, derivationBuffer.data(), derivationBuffer.size(), outKey);

	deriveKey.fill(0);

	return res;
}
