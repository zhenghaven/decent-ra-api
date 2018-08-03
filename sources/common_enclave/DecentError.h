#pragma once

#include "Enclave_t.h"

#define FUNC_ERR(X)   ocall_log_w(__FILE__, __LINE__, X); \
	                  return SGX_ERROR_UNEXPECTED;

#define LOGW(X) ocall_log_w(__FILE__, __LINE__, X);