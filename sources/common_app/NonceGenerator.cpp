#include "../common/NonceGenerator.h"

#include <stdint.h>
#include <random>

#include <cppcodec/base64_rfc4648.hpp>
//#include "../common/DataCoding.h"

namespace
{
	std::string jsonStrAlphabet("\b\t\n\f\r !\"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~");
}

std::string GenNonceForIASJson(const size_t len)
{
	//std::default_random_engine generator(std::random_device{}());
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, jsonStrAlphabet.size() - 1);

	std::string randRes;
	for (size_t i = 0; i < len; ++i)
	{
		randRes.push_back(jsonStrAlphabet[dis(gen)]);
	}

	return randRes;
}