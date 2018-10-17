#include "../DecentCrypto.h"

#include <cstring>

#include <atomic>

#include <sgx_utils.h>

#include <cppcodec/base64_rfc4648.hpp>

using namespace Decent;

namespace
{
	static sgx_report_t ConstructSgxReport()
	{
		sgx_report_t res;
		sgx_status_t enclaveRet = sgx_create_report(nullptr, nullptr, &res);
		if (enclaveRet != SGX_SUCCESS)
		{
			memset_s(&res, sizeof(res), 0, sizeof(res));
		}
		return res;
	}

	static const sgx_report_t gsk_selfReport(ConstructSgxReport());

	static General256Hash ConstructProgSelfHash()
	{
		General256Hash res = General256Hash();
		const sgx_measurement_t& enclaveHash = gsk_selfReport.body.mr_enclave;

		static_assert(res.size() == sizeof(enclaveHash.m), "Enclave hash size doesn't match!");

		std::copy(enclaveHash.m, enclaveHash.m + sizeof(enclaveHash.m), res.begin());

		return res;
	}

	//static std::shared_ptr<const TlsConfig> gsk_decentAppAppServerSideConfig;
}

const General256Hash& Crypto::GetGetProgSelfHash256()
{
	static const General256Hash hash = ConstructProgSelfHash();

	return hash;
}

//std::shared_ptr<const TlsConfig> Decent::Crypto::GetDecentAppAppServerSideConfig()
//{
//	return std::shared_ptr<const TlsConfig>();
//}

const std::string& Crypto::GetProgSelfHashBase64()
{
	static const std::string hashBase64(cppcodec::base64_rfc4648::encode(Crypto::GetGetProgSelfHash256()));
	return hashBase64;
}
