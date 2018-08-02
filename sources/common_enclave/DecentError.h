#pragma once

#define FUNC_ERR(X)   ocall_log_w(__FILE__, __LINE__, X); \
	                  return SGX_ERROR_UNEXPECTED;