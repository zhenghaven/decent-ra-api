//#if ENCLAVE_PLATFORM_SGX

#include "../Crypto.h"

#include <iterator>

#include <sgx_utils.h>
#include <sgx_trts.h>

#include "../../../Common/RuntimeException.h"
#include "../../../Common/SGX/ErrorCode.h"

using namespace Decent;
using namespace Decent::Tools;

namespace
{
	sgx_report_t ConstructSelfSgxReport()
	{
		sgx_report_t res;
		sgx_status_t sgxRet = sgx_create_report(nullptr, nullptr, &res);
		if (sgxRet != SGX_SUCCESS)
		{
			throw RuntimeException(Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_create_report"));
		}

		return res;
	}
}

namespace Decent
{
	namespace Sgx
	{
		const sgx_report_t& GetSelfSgxReport()
		{
			static sgx_report_t inst = ConstructSelfSgxReport();

			return inst;
		}
	}
}

void Tools::SecureRand(void * buf, size_t size)
{
	sgx_status_t sgxRet = sgx_read_rand(static_cast<unsigned char*>(buf), size);
	if (sgxRet != SGX_SUCCESS)
	{
		throw RuntimeException(Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_read_rand"));
	}
}

const std::vector<uint8_t>& Tools::GetSelfHash()
{
	static const std::vector<uint8_t> gsk_selfHash(std::begin(Sgx::GetSelfSgxReport().body.mr_enclave.m), std::end(Sgx::GetSelfSgxReport().body.mr_enclave.m));

	return gsk_selfHash;
}

//#endif //ENCLAVE_PLATFORM_SGX
