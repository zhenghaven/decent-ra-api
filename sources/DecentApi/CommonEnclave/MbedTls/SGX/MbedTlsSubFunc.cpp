//#if ENCLAVE_PLATFORM_SGX

#include "../../../Common/MbedTls/MbedTlsSubFunc.h"

#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include <sgx_trts.h>
#include <sgx_thread.h>

using namespace Decent;

void MbedTls::mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		sgx_is_outside_enclave(mutex, sizeof(mbedtls_threading_mutex_t)))
	{
		return;
	}

	*mutex = new sgx_thread_mutex_t;

	sgx_thread_mutex_t* sgxMutex = static_cast<sgx_thread_mutex_t*>(*mutex);
	if (sgx_thread_mutex_init(sgxMutex, nullptr) != 0)
	{
		delete sgxMutex;
		sgxMutex = nullptr;
	}
}

void MbedTls::mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		sgx_is_outside_enclave(mutex, sizeof(mbedtls_threading_mutex_t)))
	{
		return;
	}

	sgx_thread_mutex_t* sgxMutex = static_cast<sgx_thread_mutex_t*>(*mutex);
	if (sgx_thread_mutex_destroy(sgxMutex) == 0)
	{
		delete sgxMutex;
	}
}

int MbedTls::mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		sgx_is_outside_enclave(mutex, sizeof(mbedtls_threading_mutex_t)))
	{
		return -1;
	}

	sgx_thread_mutex_t* sgxMutex = static_cast<sgx_thread_mutex_t*>(*mutex);

	return sgx_thread_mutex_lock(sgxMutex) == 0 ? 0 : -1;
}

int MbedTls::mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex)
{
	if (!mutex ||
		sgx_is_outside_enclave(mutex, sizeof(mbedtls_threading_mutex_t)))
	{
		return -1;
	}

	sgx_thread_mutex_t* sgxMutex = static_cast<sgx_thread_mutex_t*>(*mutex);

	return sgx_thread_mutex_unlock(sgxMutex) == 0 ? 0 : -1;
}

extern "C" int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
	sgx_status_t enclaveRet = sgx_read_rand(output, len);
	if (enclaveRet != SGX_SUCCESS)
	{
		*olen = -1;
		return -1;
	}

	*olen = len;
	return 0;
}

extern "C" int snprintf_enclave(char *s, size_t n, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int ret = vsnprintf(s, n, fmt, ap);
	va_end(ap);
	return ret;
}

//#endif //ENCLAVE_PLATFORM_SGX
