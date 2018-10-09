#pragma once

typedef struct mbedtls_asn1_named_data mbedtls_asn1_named_data;
typedef struct mbedtls_asn1_buf mbedtls_asn1_buf;

namespace MbedTlsHelper
{
	void MbedTlsHelperDrbgInit(void *& ctx);

	int MbedTlsHelperDrbgRandom(void * ctx, unsigned char * output, size_t output_len);

	void MbedTlsHelperDrbgFree(void *& ctx);

	//Dest is allocated but not initialized.
	bool MbedTlsAsn1DeepCopy(mbedtls_asn1_buf& dest, const mbedtls_asn1_buf& src);

	//Dest is allocated but not initialized.
	bool MbedTlsAsn1DeepCopy(mbedtls_asn1_named_data& dest, const mbedtls_asn1_named_data& src);

	//Dest can be null. If it's not null, it will be freed before copy.
	bool MbedTlsAsn1DeepCopy(mbedtls_asn1_named_data*& dest, const mbedtls_asn1_named_data& src);
}
