#pragma once

#ifdef ENCLAVE_ENVIRONMENT

#ifdef ENCLAVE_SGX_ENVIRONMENT

#include <stdexcept>

#include <sgx_trts.h>

#include <mbedTLScpp/RandInterfaces.hpp>

namespace Decent
{
	class SgxRbg : public mbedTLScpp::RbgInterface
	{
	public: // Static members:

		using _BaseIntf = RbgInterface;

	public:

		/**
		 * @brief Construct a new SGX Random Bit Generator object
		 *
		 */
		SgxRbg() = default;

		/** @brief	Destructor */
		~SgxRbg()
		{}

		/**
		 * @brief Fill random bits into the given memory region.
		 *
		 * @param buf  The pointer to the beginning of the memory region.
		 * @param size The size of the memory region.
		 */
		virtual void Rand(void* buf, const size_t size) override
		{
			sgx_status_t encRet = sgx_read_rand(reinterpret_cast<uint8_t*>(buf), size);
			if (encRet != sgx_status_t::SGX_SUCCESS)
			{
				throw std::runtime_error("Decent::SgxRbg::Rand - Failed to generate random bytes.");
			}
		}
	};
}

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	using DefaultRbg = Decent::SgxRbg;
}

#endif //ENCLAVE_SGX_ENVIRONMENT

#endif // ENCLAVE_ENVIRONMENT
