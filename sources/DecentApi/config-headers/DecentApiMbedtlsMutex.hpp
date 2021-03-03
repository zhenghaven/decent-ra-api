#pragma once

#ifdef ENCLAVE_ENVIRONMENT

#ifdef ENCLAVE_SGX_ENVIRONMENT

#include <mbedtls/threading.h>

#include <sgx_thread.h>

namespace Decent
{
	struct SgxMutexIntf
	{
		static void MutexFree(mbedtls_threading_mutex_t* mutex) noexcept
		{
			if (mutex == nullptr)
			{
				return;
			}

			sgx_thread_mutex_t* cppMutex = static_cast<sgx_thread_mutex_t*>(*mutex);
			sgx_thread_mutex_destroy(cppMutex);
			delete cppMutex;
			*mutex = nullptr;
		}

		static void MutexInit(mbedtls_threading_mutex_t* mutex) noexcept
		{
			if (mutex == nullptr)
			{
				return;
			}

			sgx_thread_mutex_t* cppMutex = nullptr;
			try
			{
				*mutex = new sgx_thread_mutex_t;
				cppMutex = static_cast<sgx_thread_mutex_t*>(*mutex);
			}
			catch (...)
			{
				*mutex = nullptr;
			}

			if (sgx_thread_mutex_init(cppMutex, nullptr) != 0)
			{
				MutexFree(mutex);
			}
		}

		static int MutexLock(mbedtls_threading_mutex_t* mutex) noexcept
		{
			if (mutex == nullptr ||
				*mutex == nullptr)
			{
				return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
			}

			sgx_thread_mutex_t* cppMutex = static_cast<sgx_thread_mutex_t*>(*mutex);

			return sgx_thread_mutex_lock(cppMutex) == 0 ?
				MBEDTLS_EXIT_SUCCESS : MBEDTLS_ERR_THREADING_MUTEX_ERROR;
		}

		static int MutexUnlock(mbedtls_threading_mutex_t* mutex) noexcept
		{
			if (mutex == nullptr ||
				*mutex == nullptr)
			{
				return MBEDTLS_ERR_THREADING_BAD_INPUT_DATA;
			}

			sgx_thread_mutex_t* cppMutex = static_cast<sgx_thread_mutex_t*>(*mutex);

			return sgx_thread_mutex_unlock(cppMutex) == 0 ?
				MBEDTLS_EXIT_SUCCESS : MBEDTLS_ERR_THREADING_MUTEX_ERROR;
		}
	};

	class SgxMutexIntfInitializer
	{
	public:
		SgxMutexIntfInitializer() noexcept = default;
		~SgxMutexIntfInitializer()
		{}

		void Init() noexcept
		{
			mbedtls_threading_set_alt(
				&SgxMutexIntf::MutexInit,
				&SgxMutexIntf::MutexFree,
				&SgxMutexIntf::MutexLock,
				&SgxMutexIntf::MutexUnlock
			);
		}
	};
}

#ifndef MBEDTLSCPP_CUSTOMIZED_NAMESPACE
namespace mbedTLScpp
#else
namespace MBEDTLSCPP_CUSTOMIZED_NAMESPACE
#endif
{
	using DefaultThreadingSubInitializer = Decent::SgxMutexIntfInitializer;
}

#endif //ENCLAVE_SGX_ENVIRONMENT

#endif // ENCLAVE_ENVIRONMENT
