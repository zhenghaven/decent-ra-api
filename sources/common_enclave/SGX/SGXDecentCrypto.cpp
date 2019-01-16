#include "../DecentCrypto.h"

#include <iterator>
#include <exception>

#include <sgx_utils.h>

using namespace Decent::Crypto;

namespace
{
	static sgx_report_t ConstructSelfSgxReport()
	{
		sgx_report_t res;
		sgx_status_t enclaveRet = sgx_create_report(nullptr, nullptr, &res);
		if (enclaveRet != SGX_SUCCESS)
		{
			memset_s(&res, sizeof(res), 0, sizeof(res));
			throw std::exception("Failed to create self report!"); //This should be thrown at the program startup.
		}

		return res;
	}

	static const sgx_report_t gsk_selfReport(ConstructSelfSgxReport());

	static const std::vector<uint8_t> gsk_selfHash(std::begin(gsk_selfReport.body.mr_enclave.m), std::end(gsk_selfReport.body.mr_enclave.m));
}

const std::vector<uint8_t>& Decent::Crypto::GetSelfHash()
{
	return gsk_selfHash;
}
