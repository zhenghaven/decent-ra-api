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

#include "../Common.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/DataCoding.h"

struct DecentrNodeContext
{
	sgx_ec256_public_t m_pubKey;
	sgx_ec_key_128bit_t m_sk;
	sgx_ec_key_128bit_t m_mk;
};

typedef std::map<std::string, std::shared_ptr<const DecentrNodeContext> > DecentrNodeMapType;

namespace
{
	static std::mutex g_decentrNodesMapMutex;
	static DecentrNodeMapType g_decentrNodesMap;
	static const DecentrNodeMapType& k_decentrNodesMap = g_decentrNodesMap;
}

static bool IsBothWayAttested(const std::string& id)
{
	bool isClientAttested = SGXRAEnclave::IsClientAttested(id);
	bool isServerAttested = SGXRAEnclave::IsAttestedToServer(id);

	return isClientAttested && isServerAttested;
}

extern "C" sgx_status_t ecall_decentralized_init(const sgx_spid_t* inSpid)
{
	if (!inSpid)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	SGXRAEnclave::SetSPID(*inSpid);

	sgx_report_t selfReport;
	sgx_status_t res = sgx_create_report(nullptr, nullptr, &selfReport);
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}

	sgx_measurement_t& enclaveHash = selfReport.body.mr_enclave;
	ocall_printf("Enclave Program Hash: %s\n", SerializeStruct(enclaveHash).c_str());
	SGXRAEnclave::SetTargetEnclaveHash(SerializeStruct(enclaveHash));

	return SGX_SUCCESS;
}

extern "C" int ecall_to_decentralized_node(const char* id, int is_server)
{
	if (!id)
	{
		return 0;
	}
	if (!IsBothWayAttested(id))
	{
		return 0;
	}

	DecentrNodeContext* nodeCtx = new DecentrNodeContext;
	bool getKeyRes = false;
	if (is_server)
	{
		getKeyRes = SGXRAEnclave::ReleaseClientKeys(id, &nodeCtx->m_pubKey, &nodeCtx->m_sk, &nodeCtx->m_mk);
		SGXRAEnclave::DropRAStateToServer(id);
	}
	else
	{
		getKeyRes = SGXRAEnclave::ReleaseServerKeys(id, &nodeCtx->m_pubKey, &nodeCtx->m_sk, &nodeCtx->m_mk);
		SGXRAEnclave::DropClientRAState(id);
	}
	if (!getKeyRes)
	{
		delete nodeCtx;
		return 0;
	}

	{
		std::lock_guard<std::mutex> mapLock(g_decentrNodesMapMutex);
		g_decentrNodesMap.insert(std::make_pair(id, std::shared_ptr<const DecentrNodeContext>(nodeCtx)));
	}

	COMMON_PRINTF("Accepted New Decentralized Node: %s\n", id);

	return 1;
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

bool SGXRADecentralized::ReleaseNodeKeys(const std::string & nodeID, sgx_ec256_public_t * outSignPubKey, sgx_ec_key_128bit_t * outSK, sgx_ec_key_128bit_t * outMK)
{
	if (!outSK && !outMK && !outSignPubKey)
	{
		return false;
	}
	
	std::shared_ptr<const DecentrNodeContext> nodeCtx;
	{
		std::lock_guard<std::mutex> mapLock(g_decentrNodesMapMutex);
		auto it = k_decentrNodesMap.find(nodeID);
		if (it == k_decentrNodesMap.end())
		{
			return false;
		}
		nodeCtx = it->second;
	}

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

AESGCMCommLayer * SGXRADecentralized::ReleaseNodeKeys(const std::string & nodeID, SendFunctionType sendFunc)
{
	std::shared_ptr<const DecentrNodeContext> nodeCtx;
	{
		std::lock_guard<std::mutex> mapLock(g_decentrNodesMapMutex);
		auto it = k_decentrNodesMap.find(nodeID);
		if (it == k_decentrNodesMap.end())
		{
			return false;
		}
		nodeCtx = it->second;
	}

	AESGCMCommLayer* res = nullptr;

	res = new AESGCMCommLayer(nodeCtx->m_sk, SerializeStruct(nodeCtx->m_pubKey), sendFunc);

	SGXRADecentralized::DropNode(nodeID);

	return res;
}

#endif // USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENTRALIZED_ENCLAVE_INTERNAL
