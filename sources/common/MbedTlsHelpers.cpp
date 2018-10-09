#include "MbedTlsHelpers.h"

#include <cstring>
#include <cstdlib>

#include <mbedtls/asn1.h>

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
