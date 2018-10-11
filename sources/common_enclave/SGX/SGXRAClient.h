#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include <string>
#include <utility>
#include <memory>

#include <sgx_error.h>
#include <sgx_key_exchange.h>

#include "../../common/GeneralKeyTypes.h"

class AESGCMCommLayer;

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;

typedef struct _ias_report_t sgx_ias_report_t;

typedef uint32_t sgx_ra_context_t;

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
	bool ReleaseServerKeys(const std::string& serverID, std::unique_ptr<sgx_ec256_public_t>& outSignPubKey, std::unique_ptr<General128BitKey>& outSK, std::unique_ptr<General128BitKey>& outMK);
	AESGCMCommLayer* ReleaseServerKeys(const std::string& serverID);

	sgx_status_t ProcessRaMsg4(const std::string& serverID, const sgx_ias_report_t& inMsg4, const sgx_ec256_signature_t& inMsg4Sign, RaGetKeyFuncType raGetKeyFuncType);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
