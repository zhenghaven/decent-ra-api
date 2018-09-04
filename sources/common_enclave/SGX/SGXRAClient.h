#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include <string>
#include <utility>
#include <memory>

#include <sgx_error.h>
#include <sgx_key_exchange.h>

class AESGCMCommLayer;

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;

#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];

typedef struct _ias_report_t sgx_ias_report_t;

typedef uint32_t sgx_ra_context_t;

typedef bool(*SendFunctionType)(void* const connectionPtr, const char* senderID, const char *msg, const char* appAttach);
typedef sgx_status_t(*RaCloseCtxFuncType)(sgx_ra_context_t ctxId);
typedef sgx_status_t(*RaGetKeyFuncType)(sgx_ra_context_t, sgx_ra_key_type_t, sgx_ra_key_128_t*);

struct CtxIdWrapper
{
	const sgx_ra_context_t m_ctxId;
	RaCloseCtxFuncType m_raCloseCtxFunc;

	CtxIdWrapper() = delete;
	CtxIdWrapper(const sgx_ra_context_t ctxId, RaCloseCtxFuncType RaCloseCtxFunc) noexcept :
	m_ctxId(ctxId),
		m_raCloseCtxFunc(RaCloseCtxFunc)
	{}

	CtxIdWrapper(const CtxIdWrapper&) = delete;
	CtxIdWrapper(CtxIdWrapper&&) = delete;
	CtxIdWrapper& operator=(const CtxIdWrapper&) = delete;
	CtxIdWrapper& operator=(CtxIdWrapper&&) = delete;

	~CtxIdWrapper()
	{
		(*m_raCloseCtxFunc)(m_ctxId);
	}
};

namespace SGXRAEnclave
{
	bool AddNewServerRAState(const std::string& ServerID, const sgx_ec256_public_t& inPubKey, std::unique_ptr<CtxIdWrapper>& sgxCtxId);
	void DropRAStateToServer(const std::string& serverID);
	bool IsAttestedToServer(const std::string& serverID);
	bool ReleaseServerKeys(const std::string& serverID, sgx_ec256_public_t* outSignPubKey, sgx_ec_key_128bit_t* outSK, sgx_ec_key_128bit_t* outMK);
	AESGCMCommLayer* ReleaseServerKeys(const std::string& serverID, SendFunctionType sendFunc);

	sgx_status_t ProcessRaMsg4(const std::string& serverID, const sgx_ias_report_t& inMsg4, const sgx_ec256_signature_t& inMsg4Sign, RaGetKeyFuncType raGetKeyFuncType);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
