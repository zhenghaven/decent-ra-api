#include "SGXRAClient.h"

#include <string>
#include <map>

//#include <sgx_tkey_exchange.h>

#include "sgx_ra_tools.h"
#include "decent_tkey_exchange.h"

#include "../DecentError.h"

#include "../../common/CryptoTools.h"
#include "../../common/EnclaveRAState.h"
#include "../../common/RAKeyManager.h"
#include "../../common/SGX/sgx_ra_msg4.h"

namespace
{
	static std::map<std::string, std::pair<ServerRAState, RAKeyManager> > g_serversMap;

	//Shared objects:
	static RACryptoManager& g_cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
}

void SGXRAEnclave::DropServerRAState(const std::string& serverID)
{
	auto it = g_serversMap.find(serverID);
	if (it != g_serversMap.end())
	{
		g_serversMap.erase(it);
	}
}

bool SGXRAEnclave::IsServerAttested(const std::string & serverID)
{
	auto it = g_serversMap.find(serverID);
	return it == g_serversMap.end() ? false : (it->second.first == ServerRAState::ATTESTED);
}

RAKeyManager * SGXRAEnclave::GetServerKeysMgr(const std::string & serverID)
{
	auto it = g_serversMap.find(serverID);
	return it == g_serversMap.end() ? nullptr : &(it->second.second);
}

//RAKeyManager && SGXRAEnclave::ReleaseServerKeysMgr(const std::string & serverID)
//{
//	auto it = g_serversMap.find(serverID);
//	if (it == g_serversMap.end())
//	{
//		return RAKeyManager();
//	}
//	RAKeyManager tmpMgr(std::move(it->second.second));
//	g_serversMap.erase(it);
//	return std::move(tmpMgr);
//}


/**
* \brief	Initialize client's Remote Attestation environment.
*
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h . *NOTE:* The error here only comes from SGX runtime.
*/
extern "C" sgx_status_t ecall_init_ra_client_environment()
{
	sgx_status_t res = SGX_SUCCESS;
	if (g_cryptoMgr.GetStatus() != SGX_SUCCESS)
	{
		return g_cryptoMgr.GetStatus(); //Error return. (Error from SGX)
	}

	ocall_printf("Public Sign Key: %s\n", SerializePubKey(g_cryptoMgr.GetSignPubKey()).c_str());
	ocall_printf("Public Encr Key: %s\n", SerializePubKey(g_cryptoMgr.GetEncrPubKey()).c_str());

	return SGX_SUCCESS;
}

/**
* \brief	Get client's public encryption key.
* 
* \param	context    [in]  .
* \param	outKey     [out]  .
* 
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h .
*/
extern "C" sgx_status_t ecall_get_ra_client_pub_enc_key(sgx_ra_context_t context, sgx_ec256_public_t* outKey)
{
	if (!outKey)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	if (g_cryptoMgr.GetStatus() != SGX_SUCCESS)
	{
		return g_cryptoMgr.GetStatus();
	}

	std::memcpy(outKey, &(g_cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t));
	return SGX_SUCCESS;
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
	if (g_cryptoMgr.GetStatus() != SGX_SUCCESS)
	{
		return g_cryptoMgr.GetStatus();
	}

	std::memcpy(outKey, &(g_cryptoMgr.GetSignPubKey()), sizeof(sgx_ec256_public_t));
	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_process_ra_msg0_resp(const char* ServerID, const sgx_ec256_public_t* inPubKey, int enablePSE, sgx_ra_context_t* outContextID)
{
	auto it = g_serversMap.find(ServerID);
	if (it != g_serversMap.end())
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg0, but client ID already exist.");
	}
	g_serversMap.
		insert(
			std::make_pair<std::string, std::pair<ServerRAState, RAKeyManager> >(
				ServerID, 
				std::make_pair<ServerRAState, RAKeyManager>(ServerRAState::MSG0_DONE, RAKeyManager(*inPubKey))
			)
		);

	const sgx_ec256_private_t* prvPtr = &(g_cryptoMgr.GetEncrPriKey());
	const sgx_ec256_public_t* pubPtr = &(g_cryptoMgr.GetEncrPubKey());
	return enclave_init_ra(inPubKey, enablePSE, prvPtr, pubPtr, nullptr,outContextID); //Error return. (Error from SGX)
}

extern "C" sgx_status_t ecall_process_ra_msg2(const char* ServerID, const sgx_ec256_public_t* p_g_b, sgx_ra_context_t inContextID)
{
	sgx_status_t res = SGX_SUCCESS;
	int isGbValid = 0;

	if (p_g_b == nullptr)
	{
		FUNC_ERR_Y("Processing msg2, but g_b is nullptr.", SGX_ERROR_INVALID_PARAMETER);
	}
	res = sgx_ecc256_check_point(p_g_b, g_cryptoMgr.GetECC(), &isGbValid);
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}
	if (isGbValid == 0)
	{
		FUNC_ERR_Y("Processing msg2, but g_b is invalid.", SGX_ERROR_INVALID_PARAMETER);
	}

	auto it = g_serversMap.find(ServerID);
	if (it == g_serversMap.end()
		|| it->second.first != ServerRAState::MSG0_DONE)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg2, but client ID doesn't exist or in a invalid state.");
	}

	RAKeyManager& serverKeyMgr = it->second.second;

	serverKeyMgr.SetEncryptKey(*p_g_b);
	res = serverKeyMgr.GenerateSharedKeySet(g_cryptoMgr.GetEncrPriKey(), g_cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}

	it->second.first = ServerRAState::MSG2_DONE;

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_process_ra_msg4(const char* ServerID, const sgx_ra_msg4_t* inMsg4, sgx_ec256_signature_t* inMsg4Sign, sgx_ra_context_t inContextID)
{
	auto it = g_serversMap.find(ServerID);
	if (it == g_serversMap.end()
		|| it->second.first != ServerRAState::MSG2_DONE)
	{
		SGXRAEnclave::DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg4, but client ID doesn't exist or in a invalid state.");
	}

	RAKeyManager& serverKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	uint8_t signVerifyRes = 0;
	res = sgx_ecdsa_verify((uint8_t *)inMsg4, sizeof(sgx_ra_msg4_t), &(serverKeyMgr.GetSignKey()), inMsg4Sign, &signVerifyRes, g_cryptoMgr.GetECC());
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

	it->second.first = ServerRAState::ATTESTED;

	decent_ra_close(inContextID);

	return SGX_SUCCESS;
}
