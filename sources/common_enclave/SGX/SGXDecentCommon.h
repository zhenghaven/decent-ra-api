#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_INTERNAL

#include <string>
#include <vector>
#include <cstdint>

typedef struct _ias_report_t sgx_ias_report_t;
class DecentServerX509;

namespace DecentEnclave
{
	bool DecentReportDataVerifier(const std::string& pubSignKey, const uint8_t* initData, const std::vector<uint8_t>& inData);
	bool ProcessIasRaReport(const DecentServerX509 & inX509, const std::string& inHashStr, sgx_ias_report_t& outIasReport);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
