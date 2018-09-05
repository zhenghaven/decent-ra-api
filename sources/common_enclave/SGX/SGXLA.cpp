#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "SGXLA.h"

#include <cstring>

#include <string>
#include <memory>
#include <map>
#include <mutex>

#include <sgx_dh.h>

struct LAContext
{
	bool m_isAttested;
	sgx_dh_session_t m_session;
	std::unique_ptr<GeneralAES128BitKey> m_key;
	std::unique_ptr<sgx_dh_session_enclave_identity_t> m_identity;

	LAContext() :
		m_isAttested(false),
		m_key(new GeneralAES128BitKey),
		m_identity(new sgx_dh_session_enclave_identity_t)
	{}
};

typedef std::map<std::string, std::shared_ptr<LAContext> > PeerMapType;

namespace
{
	static std::mutex g_peerMapMutex;
	static PeerMapType g_peerMap;
	static const PeerMapType& k_serversMap = g_peerMap;
}

static inline bool IsPeerInMap(const std::string& peerId)
{
	std::lock_guard<std::mutex> mapLock(g_peerMapMutex);
	return (k_serversMap.find(peerId) != k_serversMap.cend());
}

static inline void AddPeerToMap(const std::string& peerId, std::unique_ptr<LAContext>& peerCtx)
{
	std::lock_guard<std::mutex> mapLock(g_peerMapMutex);
	g_peerMap.insert(std::make_pair(std::string(peerId), std::shared_ptr<LAContext>(peerCtx.release())));
}

extern "C" sgx_status_t ecall_sgx_la_responder_gen_msg1(const char* peerId, sgx_dh_msg1_t* const outMsg1)
{
	if (!peerId || !outMsg1)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	if (IsPeerInMap(peerId))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::unique_ptr<LAContext> peerCtx(new LAContext);

	sgx_status_t enclaveRet = SGX_SUCCESS;

	enclaveRet = sgx_dh_init_session(SGX_DH_SESSION_RESPONDER, &(peerCtx->m_session));
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	enclaveRet = sgx_dh_responder_gen_msg1(outMsg1, &(peerCtx->m_session));
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	AddPeerToMap(peerId, peerCtx);

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_sgx_la_initiator_proc_msg1(const char* peerId, const sgx_dh_msg1_t* const inMsg1, sgx_dh_msg2_t* const outMsg2)
{
	if (!peerId || !inMsg1 || !outMsg2)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	if (IsPeerInMap(peerId))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::unique_ptr<LAContext> peerCtx(new LAContext);

	sgx_status_t enclaveRet = SGX_SUCCESS;

	enclaveRet = sgx_dh_init_session(SGX_DH_SESSION_INITIATOR, &(peerCtx->m_session));
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	enclaveRet = sgx_dh_initiator_proc_msg1(inMsg1, outMsg2, &(peerCtx->m_session));
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	AddPeerToMap(peerId, peerCtx);
	
	return enclaveRet;
}

static inline std::shared_ptr<LAContext> FetchUnattestedCtx(const std::string& peerId)
{
	std::lock_guard<std::mutex> mapLock(g_peerMapMutex);
	auto it = g_peerMap.find(peerId);
	return (it != g_peerMap.end() && !it->second->m_isAttested) ? it->second : nullptr;
}

extern "C" sgx_status_t ecall_sgx_la_responder_proc_msg2(const char* peerId, const sgx_dh_msg2_t* const inMsg2, sgx_dh_msg3_t* const outMsg3)
{
	std::shared_ptr<LAContext> peerCtx(std::move(FetchUnattestedCtx(peerId)));
	if (!peerCtx)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;
	enclaveRet = sgx_dh_responder_proc_msg2(inMsg2, outMsg3, &(peerCtx->m_session), reinterpret_cast<sgx_ec_key_128bit_t*>(peerCtx->m_key->data()), peerCtx->m_identity.get());
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}
	peerCtx->m_isAttested = true;

	return enclaveRet;
}

extern "C" sgx_status_t ecall_sgx_la_initiator_proc_msg3(const char* peerId, const sgx_dh_msg3_t* const inMsg3)
{
	std::shared_ptr<LAContext> peerCtx(std::move(FetchUnattestedCtx(peerId)));
	if (!peerCtx)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;
	enclaveRet = sgx_dh_initiator_proc_msg3(inMsg3, &(peerCtx->m_session), reinterpret_cast<sgx_ec_key_128bit_t*>(peerCtx->m_key->data()), peerCtx->m_identity.get());
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}
	peerCtx->m_isAttested = true;

	return enclaveRet;
}

extern "C" void ecall_sgx_la_drop_peer(const char* peerId)
{
	SGXLAEnclave::DropPeer(peerId);
}

void SGXLAEnclave::DropPeer(const std::string & peerId)
{
	std::lock_guard<std::mutex> mapLock(g_peerMapMutex);
	auto it = g_peerMap.find(peerId);
	if (it != g_peerMap.end())
	{
		g_peerMap.erase(it);
	}
}

static inline std::shared_ptr<LAContext> FetchAndDropCtx(const std::string& peerId)
{
	std::shared_ptr<LAContext> peerCtx;
	std::lock_guard<std::mutex> mapLock(g_peerMapMutex);
	auto it = g_peerMap.find(peerId);
	if (it == g_peerMap.end() || !it->second->m_isAttested)
	{
		return nullptr;
	}
	peerCtx.swap(it->second);
	g_peerMap.erase(it);
	return std::move(peerCtx);
}

bool SGXLAEnclave::ReleasePeerKey(const std::string & peerId, std::unique_ptr<sgx_dh_session_enclave_identity_t>& outIdentity, std::unique_ptr<GeneralAES128BitKey>& outKey)
{
	std::shared_ptr<LAContext> peerCtx(std::move(FetchAndDropCtx(peerId)));
	if (!peerCtx)
	{
		return false;
	}

	outIdentity.swap(peerCtx->m_identity);
	outKey.swap(peerCtx->m_key);

	return true;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
