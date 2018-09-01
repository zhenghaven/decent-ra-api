#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_INTERNAL

#pragma once

#include <string>
#include <vector>
#include <cstdint>

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

namespace DecentEnclave
{
	bool DecentReportDataVerifier(const std::string& pubSignKey, const uint8_t* initData, const std::vector<uint8_t>& inData);
	bool ProcessIasRaReport(const std::string& inReport, const std::string& inHashStr, sgx_ec256_public_t& outPubKey, std::string* outPubKeyPem, std::string* outIasReport);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
