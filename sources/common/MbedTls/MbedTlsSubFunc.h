#pragma once

#include <mbedtls/threading.h>

namespace MbedTls
{
	void mbedtls_mutex_init(mbedtls_threading_mutex_t *mutex);
	void mbedtls_mutex_free(mbedtls_threading_mutex_t *mutex);
	int mbedtls_mutex_lock(mbedtls_threading_mutex_t *mutex);
	int mbedtls_mutex_unlock(mbedtls_threading_mutex_t *mutex);
}
