#include "Hasher.h"

#include <mbedtls/md.h>

#include "RuntimeException.h"

using namespace Decent;
using namespace Decent::MbedTlsObj;

#define CHECK_MBEDTLS_RET(VAL, FUNCSTR) {int retVal = VAL; if(retVal != MBEDTLS_SUCCESS_RET) { throw Decent::MbedTlsObj::MbedTlsException(#FUNCSTR, retVal); } }

const mbedtls_md_info_t& MbedTlsObj::GetMdInfo(HashType type)
{
	switch (type)
	{
	case HashType::SHA224:
		return *mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA224);
	case HashType::SHA256:
		return *mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256);
	case HashType::SHA384:
		return *mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA384);
	case HashType::SHA512:
		return *mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA512);
	default:
		throw MbedTlsObj::RuntimeException("Invalid hash type is given!");
	}
}

void Hasher::FreeObject(mbedtls_md_context_t * ptr)
{
	mbedtls_md_free(ptr);
	delete ptr;
}

Hasher::Hasher() :
	ObjBase(new mbedtls_md_context_t, &FreeObject)
{
	mbedtls_md_init(Get());
}

Hasher::~Hasher()
{
}

void Hasher::BatchedCalcInternal(const mbedtls_md_info_t& mdInfo, const DataListItem* dataList, size_t listLen, void * output, const size_t outSize)
{
	if (mbedtls_md_get_size(&mdInfo) != outSize)
	{
		throw MbedTlsObj::RuntimeException("Invalid output size is given!");
	}

	CHECK_MBEDTLS_RET(mbedtls_md_setup(Get(), &mdInfo, false), Hasher::CalcHash);
	CHECK_MBEDTLS_RET(mbedtls_md_starts(Get()), Hasher::CalcHash);

	int mbedRet = MBEDTLS_SUCCESS_RET;
	for (size_t i = 0; i < listLen && mbedRet == MBEDTLS_SUCCESS_RET; ++i)
	{
		mbedRet = mbedtls_md_update(Get(), static_cast<const uint8_t*>(dataList[i].m_ptr), dataList[i].size);
	}
	CHECK_MBEDTLS_RET(mbedRet, Hasher::CalcHash);

	CHECK_MBEDTLS_RET(mbedtls_md_finish(Get(), static_cast<unsigned char*>(output)), Hasher::CalcHash);
}

void Hasher::Calc(const mbedtls_md_info_t & mdInfo, const void * input, const size_t inSize, void * output, const size_t outSize)
{
	if (mbedtls_md_get_size(&mdInfo) != outSize)
	{
		throw MbedTlsObj::RuntimeException("Invalid output size is given!");
	}

	CHECK_MBEDTLS_RET(mbedtls_md(&mdInfo, static_cast<const uint8_t*>(input), inSize, static_cast<uint8_t*>(output)), Hasher::Calc);
}
