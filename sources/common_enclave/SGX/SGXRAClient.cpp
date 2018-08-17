#include "SGXRAClient.h"

#include <string>
#include <map>
#include <memory>

//#include <sgx_tkey_exchange.h>

#include "sgx_ra_tools.h"
#include "decent_tkey_exchange.h"

#include "../DecentError.h"

#include "../../common/DataCoding.h"
#include "../../common/EnclaveRAState.h"
#include "../../common/RACryptoManager.h"
#include "../../common/SGX/sgx_ra_msg4.h"

struct RAClientContext
{
	sgx_ec256_public_t m_peerSignKey;
	sgx_ec256_public_t m_peerEncrKey;
	sgx_ec_key_128bit_t m_mk = { 0 };
	sgx_ec_key_128bit_t m_sk = { 0 };
	ServerRAState m_state;

	RAClientContext(const sgx_ec256_public_t& signPub) :
		m_peerSignKey(signPub),
		m_peerEncrKey({ {0} }),
		m_state(ServerRAState::MSG0_DONE)
	{

	}
};

namespace
{
	static std::map<std::string, std::unique_ptr<RAClientContext> > g_serversMap;
	static const std::map<std::string, std::unique_ptr<RAClientContext> >& k_serversMap = g_serversMap;

	//Shared objects:
	static std::shared_ptr<RACryptoManager> g_cryptoMgr = std::make_shared<RACryptoManager>();
}

void SGXRAEnclave::SetClientCryptoManager(std::shared_ptr<RACryptoManager> cryptMgr)
{
	g_cryptoMgr = cryptMgr;
}

bool SGXRAEnclave::AddNewServerRAState(const std::string& ServerID, const sgx_ec256_public_t& inPubKey)
{
	auto it = k_serversMap.find(ServerID);
	if (it != k_serversMap.cend())
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR_Y("Processing msg0, but client ID already exist.", false);
	}
	g_serversMap.insert(std::make_pair<const std::string&, std::unique_ptr<RAClientContext>>(ServerID, std::unique_ptr<RAClientContext>(new RAClientContext(inPubKey))));

	return true;
}

void SGXRAEnclave::DropServerRAState(const std::string& serverID)
{
	auto it = k_serversMap.find(serverID);
	if (it != g_serversMap.cend())
	{
		g_serversMap.erase(it);
	}
}

bool SGXRAEnclave::IsServerAttested(const std::string & serverID)
{
	auto it = k_serversMap.find(serverID);
	return it == k_serversMap.cend() ? false : (it->second->m_state == ServerRAState::ATTESTED);
}

bool SGXRAEnclave::GetServerKeys(const std::string & serverID, sgx_ec256_public_t* outSignPubKey, sgx_ec_key_128bit_t * outSK, sgx_ec_key_128bit_t * outMK)
{
	if (!outSK && !outMK && !outSignPubKey)
	{
		return false;
	}
	auto it = g_serversMap.find(serverID);
	if (it == g_serversMap.end())
	{
		return false;
	}

	RAClientContext& clientCTX = *(it->second);

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

	return true;
}

/**
* \brief	Initialize client's Remote Attestation environment.
*
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h . *NOTE:* The error here only comes from SGX runtime.
*/
extern "C" sgx_status_t ecall_sgx_ra_client_init()
{
	sgx_status_t res = SGX_SUCCESS;
	if (g_cryptoMgr->GetStatus() != SGX_SUCCESS)
	{
		return g_cryptoMgr->GetStatus(); //Error return. (Error from SGX)
	}

	ocall_printf("Client's public Sign Key: %s\n", SerializePubKey(g_cryptoMgr->GetSignPubKey()).c_str());

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
	if (g_cryptoMgr->GetStatus() != SGX_SUCCESS)
	{
		return g_cryptoMgr->GetStatus();
	}

	std::memcpy(outKey, &(g_cryptoMgr->GetSignPubKey()), sizeof(sgx_ec256_public_t));
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
	sgx_status_t res = SGX_SUCCESS;
	int isGbValid = 0;

	if (p_g_b == nullptr)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		FUNC_ERR_Y("Processing msg2, but g_b is nullptr.", SGX_ERROR_INVALID_PARAMETER);
	}
	res = sgx_ecc256_check_point(p_g_b, g_cryptoMgr->GetECC(), &isGbValid);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		return res; //Error return. (Error from SGX)
	}
	if (isGbValid == 0)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		FUNC_ERR_Y("Processing msg2, but g_b is invalid.", SGX_ERROR_INVALID_PARAMETER);
	}

	auto it = g_serversMap.find(ServerID);
	if (it == g_serversMap.end()
		|| it->second->m_state != ServerRAState::MSG0_DONE)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg2, but client ID doesn't exist or in a invalid state.");
	}

	RAClientContext& clientCTX = *(it->second);

	res = decent_ra_get_keys(inContextID, SGX_RA_KEY_SK, &clientCTX.m_sk);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		return res; //Error return. (Error from SGX)	
	}
	res = decent_ra_get_keys(inContextID, SGX_RA_KEY_MK, &clientCTX.m_mk);
	if (res != SGX_SUCCESS)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		return res; //Error return. (Error from SGX)	
	}

	clientCTX.m_state = ServerRAState::MSG2_DONE;

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_process_ra_msg4(const char* ServerID, const sgx_ra_msg4_t* inMsg4, sgx_ec256_signature_t* inMsg4Sign, sgx_ra_context_t inContextID)
{
	auto it = g_serversMap.find(ServerID);
	if (it == g_serversMap.end()
		|| it->second->m_state != ServerRAState::MSG2_DONE)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg4, but client ID doesn't exist or in a invalid state.");
	}

	RAClientContext& clientCTX = *(it->second);

	sgx_status_t res = SGX_SUCCESS;

	uint8_t signVerifyRes = 0;
	res = sgx_ecdsa_verify((uint8_t *)inMsg4, sizeof(sgx_ra_msg4_t), &(clientCTX.m_peerSignKey), inMsg4Sign, &signVerifyRes, g_cryptoMgr->GetECC());
	if (signVerifyRes != SGX_EC_VALID)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg4, but the signature of msg 4 is invalid.");
	}
	if (inMsg4->status != ias_quote_status_t::IAS_QUOTE_OK)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg4, but the quote is rejected by the IAS.");
	}

	clientCTX.m_state = ServerRAState::ATTESTED;

	decent_ra_close(inContextID);

	return SGX_SUCCESS;
}
