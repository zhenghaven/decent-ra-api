#pragma once

#include <string>

#include <sgx_error.h>
#include <sgx_capable.h>

std::string GetSGXErrorMessage(const sgx_status_t ret);

std::string GetSGXDeviceStatusStr(const sgx_device_status_t ret);

sgx_status_t GetSGXDeviceStatus(sgx_device_status_t& res);