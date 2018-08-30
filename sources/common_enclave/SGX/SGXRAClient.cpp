#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "SGXRAClient.h"

#include <string>
#include <map>
#include <memory>
#include <mutex>

//#include <sgx_tkey_exchange.h>

#include "sgx_ra_tools.h"
#include "decent_tkey_exchange.h"

#include "../Common.h"

#include "../../common/DataCoding.h"
#include "../../common/EnclaveAsyKeyContainer.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/SGX/sgx_ra_msg4.h"

enum class ServerRAState
{
	MSG0_DONE,
	MSG2_DONE,
	ATTESTED, //MSG4_DONE,
};

struct RAClientContext
{
	sgx_ec256_public_t m_peerSignKey;
	sgx_ec256_public_t m_peerEncrKey;
	sgx_ec_key_128bit_t m_mk = { 0 };
	sgx_ec_key_128bit_t m_sk = { 0 };
	ServerRAState m_state;
	std::mutex m_mutex;

	RAClientContext(const sgx_ec256_public_t& signPub) :
		m_peerSignKey(signPub),
		m_peerEncrKey({ {0} }),
		m_state(ServerRAState::MSG0_DONE)
	{

	}
};

typedef std::map<std::string, std::shared_ptr<RAClientContext> > ServerMapType;

namespace
{
	static std::mutex g_serversMapMutex;
	static ServerMapType g_serversMap;
	static const ServerMapType& k_serversMap = g_serversMap;
}

bool SGXRAEnclave::AddNewServerRAState(const std::string& ServerID, const sgx_ec256_public_t& inPubKey)
{
	std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
	auto it = k_serversMap.find(ServerID);
	if (it != k_serversMap.cend())
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR_Y("Processing msg0, but client ID already exist.", false);
	}
	g_serversMap.insert(std::make_pair(ServerID, std::shared_ptr<RAClientContext>(new RAClientContext(inPubKey))));

	return true;
}

void SGXRAEnclave::DropRAStateToServer(const std::string& serverID)
{
	std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
	auto it = k_serversMap.find(serverID);
	if (it != k_serversMap.cend())
	{
		g_serversMap.erase(it);
	}
}

bool SGXRAEnclave::IsAttestedToServer(const std::string & serverID)
{
	std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
	auto it = k_serversMap.find(serverID);
	return it == k_serversMap.cend() ? false : (it->second->m_state == ServerRAState::ATTESTED);
}

bool SGXRAEnclave::ReleaseServerKeys(const std::string & serverID, sgx_ec256_public_t* outSignPubKey, sgx_ec_key_128bit_t * outSK, sgx_ec_key_128bit_t * outMK)
{
	if (!outSK && !outMK && !outSignPubKey)
	{
		return false;
	}
	std::shared_ptr<RAClientContext> clientCTXPtr;
	{
		std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
		auto it = g_serversMap.find(serverID);
		if (it == g_serversMap.end())
		{
			return false;
		}
		clientCTXPtr = it->second;
	}

	RAClientContext& clientCTX = *clientCTXPtr;
	std::lock_guard<std::mutex> ctxLock(clientCTX.m_mutex);

	if (outSK)
	{
		std::memcpy(outSK, &clientCTX.m_sk, sizeof(sgx_ec_key_128bit_t));
	}
	if (outMK)
	{
		std::memcpy(outMK, &clientCTX.m_mk, sizeof(sgx_ec_key_128bit_t));
	}
	if (outSignPubKey)
	{
		std::memcpy(outSignPubKey, &clientCTX.m_peerSignKey, sizeof(sgx_ec256_public_t));
	}

	SGXRAEnclave::DropRAStateToServer(serverID);

	return true;
}

AESGCMCommLayer* SGXRAEnclave::ReleaseServerKeys(const std::string & serverID, SendFunctionType sendFunc)
{
	std::shared_ptr<RAClientContext> clientCTXPtr;
	{
		std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
		auto it = g_serversMap.find(serverID);
		if (it == g_serversMap.end())
		{
			return nullptr;
		}
		clientCTXPtr = it->second;
	}

	RAClientContext& clientCTX = *clientCTXPtr;
	AESGCMCommLayer* res = nullptr;
	{
		std::lock_guard<std::mutex> ctxLock(clientCTX.m_mutex);
		res = new AESGCMCommLayer(clientCTX.m_sk, SerializeStruct(*EnclaveAsyKeyContainer::GetInstance().GetSignPubKey()), sendFunc);
	}
	SGXRAEnclave::DropRAStateToServer(serverID);
	return res;
}

/**
* \brief	Initialize client's Remote Attestation environment.
*
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h . *NOTE:* The error here only comes from SGX runtime.
*/
extern "C" sgx_status_t ecall_sgx_ra_client_init()
{
	sgx_status_t res = SGX_SUCCESS;
	if (!EnclaveAsyKeyContainer::GetInstance().IsValid())
	{
		return SGX_ERROR_UNEXPECTED; //Error return. (Error from SGX)
	}

	return SGX_SUCCESS;
}

/**
* \brief	Terminate client's Remote Attestation environment.
*
*/
extern "C" void ecall_sgx_ra_client_terminate()
{
	
}

/**
* \brief	Get client's public signing key.
*
* \param	outKey     [out]  .
*
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h .
*/
extern "C" sgx_status_t ecall_get_ra_client_pub_sig_key(sgx_ec256_public_t* outKey)
{
	if (!outKey)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	if (!EnclaveAsyKeyContainer::GetInstance().IsValid())
	{
		return SGX_ERROR_UNEXPECTED; //Error return. (Error from SGX)
	}

	std::shared_ptr<const sgx_ec256_public_t> signPub = EnclaveAsyKeyContainer::GetInstance().GetSignPubKey();
	std::memcpy(outKey, signPub.get(), sizeof(sgx_ec256_public_t));
	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_process_ra_msg0_resp(const char* ServerID, const sgx_ec256_public_t* inPubKey, int enablePSE, sgx_ra_context_t* outContextID)
{
	if (!ServerID || !inPubKey || !outContextID || 
		!SGXRAEnclave::AddNewServerRAState(ServerID, *inPubKey))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return enclave_init_sgx_ra(inPubKey, enablePSE, nullptr, outContextID); //Error return. (Error from SGX)
}

extern "C" sgx_status_t ecall_process_ra_msg2(const char* ServerID, const sgx_ec256_public_t* p_g_b, sgx_ra_context_t inContextID)
{
	if (!ServerID || !p_g_b)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t res = SGX_SUCCESS;
	int isGbValid = 0;

	if (p_g_b == nullptr)
	{
		SGXRAEnclave::DropRAStateToServer(ServerID);
		FUNC_ERR_Y("Processing msg2, but g_b is nullptr.", SGX_ERROR_INVALID_PARAMETER);
	}

	{
		sgx_ecc_state_handle_t eccState;
		res = sgx_ecc256_open_context(&eccState);
		if (res != SGX_SUCCESS)
		{
			SGXRAEnclave::DropRAStateToServer(ServerID);
			return res; //Error return. (Error from SGX)
		}

		res = sgx_ecc256_check_point(p_g_b, eccState, &isGbValid);
		if (res != SGX_SUCCESS)
		{
			SGXRAEnclave::DropRAStateToServer(ServerID);
			return res; //Error return. (Error from SGX)
		}

		sgx_ecc256_close_context(eccState);
	}

	if (isGbValid == 0)
	{
		SGXRAEnclave::DropRAStateToServer(ServerID);
		FUNC_ERR_Y("Processing msg2, but g_b is invalid.", SGX_ERROR_INVALID_PARAMETER);
	}

	std::shared_ptr<RAClientContext> clientCTXPtr;
	bool isValidState = false;
	{
		std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
		auto it = g_serversMap.find(ServerID);
		isValidState = (it != g_serversMap.end() && it->second->m_state == ServerRAState::MSG0_DONE);
		clientCTXPtr = it->second;
	}
	if (!isValidState)
	{
		SGXRAEnclave::DropRAStateToServer(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg2, but client ID doesn't exist or in a invalid state.");
	}

	RAClientContext& clientCTX = *clientCTXPtr;
	std::lock_guard<std::mutex> ctxLock(clientCTX.m_mutex);

	res = decent_ra_get_keys(inContextID, SGX_RA_KEY_SK, &clientCTX.m_sk);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropRAStateToServer(ServerID);
		return res; //Error return. (Error from SGX)	
	}
	res = decent_ra_get_keys(inContextID, SGX_RA_KEY_MK, &clientCTX.m_mk);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropRAStateToServer(ServerID);
		return res; //Error return. (Error from SGX)	
	}

	clientCTX.m_state = ServerRAState::MSG2_DONE;

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_process_ra_msg4(const char* ServerID, const sgx_ra_msg4_t* inMsg4, sgx_ec256_signature_t* inMsg4Sign, sgx_ra_context_t inContextID)
{
	if (!ServerID || !inMsg4 || !inMsg4Sign)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::shared_ptr<RAClientContext> clientCTXPtr;
	bool isValidState = false;
	{
		std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
		auto it = g_serversMap.find(ServerID);
		isValidState = (it != g_serversMap.end() && it->second->m_state == ServerRAState::MSG2_DONE);
		clientCTXPtr = it->second;
	}
	if (!isValidState)
	{
		SGXRAEnclave::DropRAStateToServer(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg4, but client ID doesn't exist or in a invalid state.");
	}

	RAClientContext& clientCTX = *clientCTXPtr;
	std::lock_guard<std::mutex> ctxLock(clientCTX.m_mutex);

	sgx_status_t res = SGX_SUCCESS;
	
	{
		sgx_ecc_state_handle_t eccState;
		res = sgx_ecc256_open_context(&eccState);
		if (res != SGX_SUCCESS)
		{
			SGXRAEnclave::DropRAStateToServer(ServerID);
			return res; //Error return. (Error from SGX)
		}

		uint8_t signVerifyRes = 0;
		res = sgx_ecdsa_verify((uint8_t *)inMsg4, sizeof(sgx_ra_msg4_t), &(clientCTX.m_peerSignKey), inMsg4Sign, &signVerifyRes, eccState);
		if (signVerifyRes != SGX_EC_VALID)
		{
			SGXRAEnclave::DropRAStateToServer(ServerID);
			//Error return. (Error caused by invalid input.)
			FUNC_ERR("Processing msg4, but the signature of msg 4 is invalid.");
		}

		sgx_ecc256_close_context(eccState);
	}

	if (inMsg4->status != ias_quote_status_t::IAS_QUOTE_OK)
	{
		SGXRAEnclave::DropRAStateToServer(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg4, but the quote is rejected by the IAS.");
	}

	clientCTX.m_state = ServerRAState::ATTESTED;

	decent_ra_close(inContextID);

	return SGX_SUCCESS;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
