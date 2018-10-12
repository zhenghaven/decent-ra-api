#pragma once

#include <cstdint>

#include <string>
#include <vector>
#include <array>

#include "GeneralKeyTypes.h"

typedef struct mbedtls_asn1_named_data mbedtls_asn1_named_data;
typedef struct mbedtls_asn1_buf mbedtls_asn1_buf;

namespace MbedTlsHelper
{
	void DrbgInit(void *& ctx);

	int DrbgRandom(void * ctx, unsigned char * output, size_t output_len);

	void DrbgFree(void *& ctx);

	//Dest is allocated but not initialized.
	bool MbedTlsAsn1DeepCopy(mbedtls_asn1_buf& dest, const mbedtls_asn1_buf& src);

	//Dest is allocated but not initialized.
	bool MbedTlsAsn1DeepCopy(mbedtls_asn1_named_data& dest, const mbedtls_asn1_named_data& src);

	//Dest can be null. If it's not null, it will be freed before copy.
	bool MbedTlsAsn1DeepCopy(mbedtls_asn1_named_data*& dest, const mbedtls_asn1_named_data& src);

	struct HashDataListItem
	{
		const void* m_ptr;
		size_t size;
	};
	typedef std::vector<HashDataListItem> HashDataList;
	struct HashListMode	{HashListMode() = default;};
	const HashListMode hashListMode;

	bool CalcHashSha256(const HashListMode, const HashDataList& dataList, General256Hash& hash);

	bool CalcHashSha256(const void* dataPtr, const size_t size, General256Hash& hash);

	template<typename Container>
	bool CalcHashSha256(const Container& data, General256Hash& hash)
	{
		return CalcHashSha256(data.data(), data.size(), hash);
	}

	bool CalcCmacAes128(const General128BitKey& key, const uint8_t* data, size_t dataSize, General128Tag& outTag);

	bool VerifyCmacAes128(const General128BitKey& key, const uint8_t* data, size_t dataSize, const General128Tag& inTag);

	bool CkdfAes128(const uint8_t* key, size_t keySize, const char* label, size_t labelLen, General128BitKey& outKey);

	template<size_t keySize>
	bool CkdfAes128(const std::array<uint8_t, keySize>& key, const std::string& label, General128BitKey& outKey)
	{
		return CkdfAes128(key.data(), key.size(), label.data(), label.size(), outKey);
	}

}

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

	int consttime_memequal(const void *b1, const void *b2, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */