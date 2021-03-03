#pragma once

//#define ENCLAVE_ENVIRONMENT
//#define ENCLAVE_SGX_ENVIRONMENT

#include <string>
#include <vector>

#include <mbedTLScpp/Internal/Codec.hpp>

#if defined(ENCLAVE_ENVIRONMENT)

#if defined(ENCLAVE_SGX_ENVIRONMENT)
#include <sgx_utils.h>

#include "../SGX/ErrorCode.h"
#endif // defined(ENCLAVE_SGX_ENVIRONMENT)

#endif // defined(ENCLAVE_ENVIRONMENT)

#include "../Exceptions.h"

namespace Decent
{
	namespace Tools
	{
#if defined(ENCLAVE_ENVIRONMENT)

#if defined(ENCLAVE_SGX_ENVIRONMENT)
		namespace Sgx
		{
			inline sgx_report_t ConstructSelfReport()
			{
				sgx_report_t res;
				sgx_status_t sgxRet = sgx_create_report(nullptr, nullptr, &res);
				if (sgxRet != SGX_SUCCESS)
				{
					throw RuntimeException(Decent::Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_create_report"));
				}

				return res;
			}

			inline const sgx_report_t& GetSelfReport()
			{
				static sgx_report_t inst = ConstructSelfReport();

				return inst;
			}
		}
#endif // defined(ENCLAVE_SGX_ENVIRONMENT)

		/**
		 * \brief	Gets self hash in binary.
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \return	A binary array.
		 */
		const std::vector<uint8_t>& GetSelfHash();

		/**
		 * \brief	Gets self hash in HEX encoded string.
		 *
		 * \exception	Decent::RuntimeException	Thrown when underlying function call failed.
		 *
		 * \return	The HEX encoded string.
		 */
		inline const std::string& GetSelfHashHexStr()
		{
			using namespace mbedTLScpp;

			static const std::string hexStr =
				Internal::Bytes2HEXLitEnd(CtnFullR(GetSelfHash()));

			return hexStr;
		}

#endif // defined(ENCLAVE_ENVIRONMENT)
	}
}

#if defined(ENCLAVE_ENVIRONMENT)

#if defined(ENCLAVE_SGX_ENVIRONMENT)

inline const std::vector<uint8_t>& Decent::Tools::GetSelfHash()
{
	using namespace Decent::Tools;

	static const std::vector<uint8_t> gsk_selfHash(
		std::begin(Sgx::GetSelfReport().body.mr_enclave.m),
		std::end(Sgx::GetSelfReport().body.mr_enclave.m)
	);

	return gsk_selfHash;
}

#endif // defined(ENCLAVE_SGX_ENVIRONMENT)

#endif // defined(ENCLAVE_ENVIRONMENT)

