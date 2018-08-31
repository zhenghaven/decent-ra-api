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
	sgx_key_128bit_t m_key;
	sgx_dh_session_enclave_identity_t m_identity;

	LAContext() :
		m_isAttested(false),
		m_key{ 0 }
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

extern "C" sgx_status_t ecall_sgx_la_responder_proc_msg2(const char* peerId, const sgx_dh_msg2_t* const inMsg2, sgx_dh_msg3_t* const outMsg3)
{
	std::shared_ptr<LAContext> peerCtx;
	{
		std::lock_guard<std::mutex> mapLock(g_peerMapMutex);
		auto it = g_peerMap.find(peerId);
		if (it == g_peerMap.end())
		{
			return SGX_ERROR_INVALID_PARAMETER;
		}
		peerCtx = it->second;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;
	enclaveRet = sgx_dh_responder_proc_msg2(inMsg2, outMsg3, &(peerCtx->m_session), &(peerCtx->m_key), &(peerCtx->m_identity));
	if (enclaveRet != SGX_SUCCESS)
	{
		SGXLAEnclave::DropPeer(peerId);
	}
	peerCtx->m_isAttested = true;

	return enclaveRet;
}

extern "C" sgx_status_t ecall_sgx_la_initiator_proc_msg3(const char* peerId, const sgx_dh_msg3_t* const inMsg3)
{
	std::shared_ptr<LAContext> peerCtx;
	{
		std::lock_guard<std::mutex> mapLock(g_peerMapMutex);
		auto it = g_peerMap.find(peerId);
		if (it == g_peerMap.end())
		{
			return SGX_ERROR_INVALID_PARAMETER;
		}
		peerCtx = it->second;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;
	enclaveRet = sgx_dh_initiator_proc_msg3(inMsg3, &(peerCtx->m_session), &(peerCtx->m_key), &(peerCtx->m_identity));
	if (enclaveRet != SGX_SUCCESS)
	{
		SGXLAEnclave::DropPeer(peerId);
	}
	peerCtx->m_isAttested = true;

	return enclaveRet;
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

bool SGXLAEnclave::ReleasePeerKey(const std::string & peerId, sgx_dh_session_enclave_identity_t & outIdentity, sgx_ec_key_128bit_t & outKey)
{
	std::shared_ptr<LAContext> peerCtx;
	{
		std::lock_guard<std::mutex> mapLock(g_peerMapMutex);
		auto it = g_peerMap.find(peerId);
		if (it == g_peerMap.end())
		{
			return false;
		}
		peerCtx = it->second;
	}

	if (!peerCtx->m_isAttested)
	{
		return false;
	}

	std::memcpy(outKey, (peerCtx->m_key), sizeof(sgx_ec_key_128bit_t));
	std::memcpy(&outIdentity, &(peerCtx->m_identity), sizeof(sgx_ec_key_128bit_t));

	SGXLAEnclave::DropPeer(peerId);

	return true;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
