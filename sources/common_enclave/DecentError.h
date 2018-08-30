#pragma once

#ifndef DECENT_ERROR_H
#define DECENT_ERROR_H

#define FUNC_ERR(X)   ocall_log_w(__FILE__, __LINE__, X); \
	                  return SGX_ERROR_UNEXPECTED;

#define FUNC_ERR_Y(X, Y)  ocall_log_w(__FILE__, __LINE__, X); \
	                    return Y;

#endif // !DECENT_ERROR_H
