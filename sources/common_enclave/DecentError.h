#pragma once

#ifndef DECENT_ERROR_H
#define DECENT_ERROR_H

#include <Enclave_t.h>

#define FUNC_ERR(X)   ocall_log_w(__FILE__, __LINE__, X); \
	                  return SGX_ERROR_UNEXPECTED;

#define FUNC_ERR_Y(X, Y)  ocall_log_w(__FILE__, __LINE__, X); \
	                    return Y;

#define LOGW(X) ocall_log_w(__FILE__, __LINE__, X);


#if defined(__cplusplus)
extern "C" {
#endif

	void ocall_printf(const char *fmt, ...);

#if defined(__cplusplus)
}
#endif

#endif // !DECENT_ERROR_H
