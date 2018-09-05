#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL

#pragma once

#include <string>
#include <memory>

#include "../../common/GeneralKeyTypes.h"

class AESGCMCommLayer;

typedef bool(*SendFunctionType)(void* const connectionPtr, const char* senderID, const char *msg, const char* appAttach);

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

namespace std
{
	template <class _Tp, size_t _Size>
	struct array;
}
typedef std::array<uint8_t, 16> GeneralAES128BitKey;

typedef struct _ias_report_t sgx_ias_report_t;

namespace SGXRADecentralized
{
	void DropNode(const std::string& nodeID);
	bool IsNodeAttested(const std::string& nodeID);
	bool ReleaseNodeKeys(const std::string& nodeID, std::unique_ptr<sgx_ias_report_t>& outIasReport, std::unique_ptr<sgx_ec256_public_t>& outSignPubKey, std::unique_ptr<GeneralAES128BitKey>& outSK, std::unique_ptr<GeneralAES128BitKey>& outMK);
	AESGCMCommLayer* ReleaseNodeKeys(const std::string& nodeID, SendFunctionType sendFunc, std::unique_ptr<sgx_ias_report_t>& outIasReport);
}

#endif // USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL
