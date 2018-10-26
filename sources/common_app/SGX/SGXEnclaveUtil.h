#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include <string>

#include <sgx_error.h>
#include <sgx_capable.h>

std::string GetSGXErrorMessage(const sgx_status_t ret);

std::string GetSGXDeviceStatusStr(const sgx_device_status_t ret);

sgx_status_t GetSGXDeviceStatus(sgx_device_status_t& res);

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
