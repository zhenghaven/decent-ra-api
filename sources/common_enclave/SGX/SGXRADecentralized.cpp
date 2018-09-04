#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL

#include "SGXRADecentralized.h"

#include <mutex>
#include <map>
#include <memory>

#include <sgx_utils.h>
#include <sgx_tcrypto.h>
#include <sgx_ecp_types.h>

#include "SGXRAClient.h"
#include "../../common/SGX/SGXRAServiceProvider.h"
#include "../../common/SGX/ias_report.h"
#include "../../common/SGX/IasReport.h"

#include "../Common.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/DataCoding.h"

struct DecentrNodeContext
{
	sgx_ec256_public_t m_pubKey;
	sgx_ec_key_128bit_t m_sk;
	sgx_ec_key_128bit_t m_mk;
	sgx_ias_report_t m_iasReport;
};

typedef std::map<std::string, std::shared_ptr<const DecentrNodeContext> > DecentrNodeMapType;

namespace
{
	//Assume this is set correctly during init and no change afterwards.
	static std::shared_ptr<const std::string> g_selfHash = std::make_shared<const std::string>("");

	static std::mutex g_decentrNodesMapMutex;
	static DecentrNodeMapType g_decentrNodesMap;
	static const DecentrNodeMapType& k_decentrNodesMap = g_decentrNodesMap;
}

static inline void SetSelfEnclaveHash(const std::string & hashBase64)
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&g_targetHash, std::make_shared<const std::string>(hashBase64));
#else
	g_selfHash = std::make_shared<const std::string>(hashBase64);
#endif // DECENT_THREAD_SAFETY_HIGH
}

static inline const std::string GetSelfEnclaveHash()
{
#ifdef DECENT_THREAD_SAFETY_HIGH
	return *std::atomic_load(&g_targetHash);
#else
	return *g_selfHash;
#endif // DECENT_THREAD_SAFETY_HIGH
}

static inline bool IsBothWayAttested(const std::string& id)
{
	bool isClientAttested = SGXRAEnclave::IsClientAttested(id);
	bool isServerAttested = SGXRAEnclave::IsAttestedToServer(id);

	return isClientAttested && isServerAttested;
}

extern "C" sgx_status_t ecall_decentralized_init(const sgx_spid_t* in_spid)
{
	if (!in_spid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	SGXRAEnclave::SetSPID(*in_spid);

	sgx_report_t selfReport;
	sgx_status_t res = sgx_create_report(nullptr, nullptr, &selfReport);
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}

	sgx_measurement_t& enclaveHash = selfReport.body.mr_enclave;
	ocall_printf("Enclave Program Hash: %s\n", SerializeStruct(enclaveHash).c_str());
	SetSelfEnclaveHash(SerializeStruct(enclaveHash));

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_to_decentralized_node(const char* id, int is_server)
{
	if (!id)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	if (!IsBothWayAttested(id))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	DecentrNodeContext* nodeCtx = new DecentrNodeContext;
	bool getKeyRes = SGXRAEnclave::ReleaseClientKeys(id, nodeCtx->m_iasReport, &nodeCtx->m_pubKey, &nodeCtx->m_sk, &nodeCtx->m_mk);

	if (is_server)
	{
		SGXRAEnclave::DropRAStateToServer(id);
	}
	else
	{
		getKeyRes = getKeyRes && SGXRAEnclave::ReleaseServerKeys(id, &nodeCtx->m_pubKey, &nodeCtx->m_sk, &nodeCtx->m_mk);
	}
	if (!getKeyRes)
	{
		delete nodeCtx;
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_measurement_t targetHash;
	DeserializeStruct(targetHash, GetSelfEnclaveHash());
	if (!consttime_memequal(&nodeCtx->m_iasReport.m_quote.report_body.mr_enclave, &targetHash, sizeof(sgx_measurement_t)))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}


	{
		std::lock_guard<std::mutex> mapLock(g_decentrNodesMapMutex);
		g_decentrNodesMap.insert(std::make_pair(id, std::shared_ptr<const DecentrNodeContext>(nodeCtx)));
	}

	COMMON_PRINTF("Accepted New Decentralized Node: %s\n", id);

	return SGX_SUCCESS;
}

void SGXRADecentralized::DropNode(const std::string & nodeID)
{
	std::lock_guard<std::mutex> mapLock(g_decentrNodesMapMutex);
	auto it = g_decentrNodesMap.find(nodeID);
	if (it != g_decentrNodesMap.cend())
	{
		g_decentrNodesMap.erase(it);
	}
}

bool SGXRADecentralized::IsNodeAttested(const std::string & nodeID)
{
	std::lock_guard<std::mutex> mapLock(g_decentrNodesMapMutex);
	return k_decentrNodesMap.find(nodeID) != k_decentrNodesMap.cend();
}

static inline std::shared_ptr<const DecentrNodeContext> FetchNodeCtx(const std::string & nodeID)
{
	std::lock_guard<std::mutex> mapLock(g_decentrNodesMapMutex);
	auto it = k_decentrNodesMap.find(nodeID);
	return (it != k_decentrNodesMap.end()) ? it->second : nullptr;
}

bool SGXRADecentralized::ReleaseNodeKeys(const std::string & nodeID, sgx_ias_report_t& outIasReport, sgx_ec256_public_t * outSignPubKey, sgx_ec_key_128bit_t * outSK, sgx_ec_key_128bit_t * outMK)
{
	if (!outSK && !outMK && !outSignPubKey)
	{
		return false;
	}
	
	std::shared_ptr<const DecentrNodeContext> nodeCtx(std::move(FetchNodeCtx(nodeID)));
	if (!nodeCtx)
	{
		return false;
	}

	std::memcpy(&outIasReport, &nodeCtx->m_iasReport, sizeof(outIasReport));

	if (outSK)
	{
		std::memcpy(outSK, &nodeCtx->m_sk, sizeof(sgx_ec_key_128bit_t));
	}
	if (outMK)
	{
		std::memcpy(outMK, &nodeCtx->m_mk, sizeof(sgx_ec_key_128bit_t));
	}
	if (outSignPubKey)
	{
		std::memcpy(outSignPubKey, &nodeCtx->m_pubKey, sizeof(sgx_ec256_public_t));
	}

	SGXRADecentralized::DropNode(nodeID);

	return true;
}

AESGCMCommLayer * SGXRADecentralized::ReleaseNodeKeys(const std::string & nodeID, SendFunctionType sendFunc, sgx_ias_report_t& outIasReport)
{
	std::shared_ptr<const DecentrNodeContext> nodeCtx(std::move(FetchNodeCtx(nodeID)));
	if (!nodeCtx)
	{
		return false;
	}

	std::memcpy(&outIasReport, &nodeCtx->m_iasReport, sizeof(outIasReport));

	AESGCMCommLayer* res = new AESGCMCommLayer(nodeCtx->m_sk, SerializeStruct(nodeCtx->m_pubKey), sendFunc);

	SGXRADecentralized::DropNode(nodeID);

	return res;
}

#endif // USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL
