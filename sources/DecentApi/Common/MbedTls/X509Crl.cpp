#include "X509Crl.h"

#include <mbedtls/x509_crl.h>
#include <mbedtls/pem.h>

#include "MbedTlsException.h"
#include "Internal/Base64Sizes.h"

using namespace Decent::MbedTlsObj;

namespace
{
	static constexpr char const PEM_BEGIN_CRL[] = "-----BEGIN X509 CRL-----\n";
	static constexpr char const PEM_END_CRL[] = "-----END X509 CRL-----\n";

	static constexpr size_t PEM_CRL_HEADER_SIZE = sizeof(PEM_BEGIN_CRL) - 1;
	static constexpr size_t PEM_CRL_FOOTER_SIZE = sizeof(PEM_END_CRL) - 1;

	inline constexpr size_t CalcPemMaxBytes(size_t derMaxSize, size_t headerSize, size_t footerSize)
	{
		using namespace detail;

		return headerSize +                        // Header size
			Base64EncodedSize(derMaxSize) +        // Base64 encoded size
			(Base64EncodedSize(derMaxSize) / 64) + //'\n' for each line
			footerSize +                           // Footer size
			1;                                     // null terminator
	}
}

void X509Crl::FreeObject(mbedtls_x509_crl * ptr)
{
	mbedtls_x509_crl_free(ptr);
	delete ptr;
}

X509Crl::X509Crl(X509Crl && rhs) :
	ObjBase(std::forward<ObjBase>(rhs))
{
}

X509Crl::X509Crl(const std::string & pem) :
	X509Crl()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509_crl_parse, Get(), reinterpret_cast<const uint8_t*>(pem.c_str()), pem.size() + 1);
}

X509Crl::X509Crl(const std::vector<uint8_t>& der) :
	X509Crl()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_x509_crl_parse, Get(), der.data(), der.size());
}

X509Crl::~X509Crl()
{
}

std::string X509Crl::GetPem() const
{
	NullCheck();

	size_t pemLen = CalcPemMaxBytes(Get()->raw.len, PEM_CRL_HEADER_SIZE, PEM_CRL_FOOTER_SIZE);
	std::string pem(pemLen, 0);

	size_t olen = 0;

	CALL_MBEDTLS_C_FUNC(mbedtls_pem_write_buffer, PEM_BEGIN_CRL, PEM_END_CRL,
		Get()->raw.p, Get()->raw.len,
		reinterpret_cast<uint8_t*>(&pem[0]), pem.size(),
		&olen);

	pem.resize(olen);

	return pem;
}

std::vector<uint8_t> X509Crl::GetDer() const
{
	NullCheck();

	return std::vector<uint8_t>(Get()->raw.p, Get()->raw.p + Get()->raw.len);
}

X509Crl::X509Crl() :
	ObjBase(new mbedtls_x509_crl, &FreeObject)
{
	mbedtls_x509_crl_init(Get());
}

X509Crl::X509Crl(mbedtls_x509_crl * ptr, FreeFuncType freeFunc) :
	ObjBase(ptr, freeFunc)
{
}
