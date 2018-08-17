#include "../common/NonceGenerator.h"

#include <stdint.h>
#include <vector>

#include <sgx_trts.h>

#include <cppcodec/base64_rfc4648.hpp>
//#include "../common/DataCoding.h"

namespace
{
	std::string jsonStrAlphabet("\b\t\n\f\r !\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");
}

std::string GenNonceForIASJson(const size_t len)
{
	size_t dataSize = (len / 4) * 3;
	static std::vector<uint8_t> randData(dataSize, 0);
	randData.resize(dataSize);

	sgx_status_t ret = SGX_SUCCESS;
	std::string randRes;

	ret = sgx_read_rand(&randData[0], dataSize);
	randRes = cppcodec::base64_rfc4648::encode(randData);

	return randRes;
}