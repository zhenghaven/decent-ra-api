#include "SgxServiceProvider.h"

#include <sgx_quote.h>

#include <cppcodec/hex_default_upper.hpp>

#include "../Tools/JsonParser.h"

using namespace Decent::Tools;
using namespace Decent::AppConfig;

namespace
{
	static std::unique_ptr<sgx_spid_t> ParseSpid(const Json::Value & json)
	{
		std::unique_ptr<sgx_spid_t> res = std::make_unique<sgx_spid_t>();
		std::string spidStr;

#ifdef SIMULATING_ENCLAVE
		try
		{
#endif // SIMULATING_ENCLAVE
			spidStr = JsonGetStringFromObject(json, SgxServiceProvider::sk_labelSpid);
#ifdef SIMULATING_ENCLAVE
		}
		catch (const JsonParseError&)
		{
			return res;
		}
#endif // SIMULATING_ENCLAVE

		if (sizeof(sgx_spid_t) != cppcodec::hex_upper::decoded_max_size(spidStr.size()))
		{
			throw JsonParseError();
		}

		cppcodec::hex_upper::decode(reinterpret_cast<char*>(res.get()), sizeof(sgx_spid_t), spidStr);

		return res;
	}

	static std::string ParseSubsriptionKey(const Json::Value & json)
	{
#ifdef SIMULATING_ENCLAVE
		try
		{
#endif // SIMULATING_ENCLAVE
			return JsonGetStringFromObject(json, SgxServiceProvider::sk_labelSubscriptionKey);
#ifdef SIMULATING_ENCLAVE
		}
		catch (const JsonParseError&)
		{
			return std::string();
		}
#endif // SIMULATING_ENCLAVE
	}
}

constexpr char const SgxServiceProvider::sk_defaultLabel[];

constexpr char const SgxServiceProvider::sk_labelSpid[];
constexpr char const SgxServiceProvider::sk_labelSubscriptionKey[];

SgxServiceProvider::SgxServiceProvider(const Decent::Tools::JsonValue & json) :
	m_spid(ParseSpid(json)),
	m_subsriptionKey(ParseSubsriptionKey(json))
{
}

SgxServiceProvider::~SgxServiceProvider()
{
}
