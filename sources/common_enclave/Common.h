#pragma once

#define COMMON_PRINTF ocall_printf

#define LOGW(...) ocall_log_w(__FILE__, __LINE__, __VA_ARGS__);

#if defined(__cplusplus)
extern "C" {
#endif

	void ocall_printf(const char *fmt, ...);

	void ocall_printf_w(const char *fmt, ...);

	void ocall_printf_e(const char *fmt, ...);

	void ocall_log_w(const char *file, int line, const char *fmt, ...);

#if defined(__cplusplus)
}
#endif
