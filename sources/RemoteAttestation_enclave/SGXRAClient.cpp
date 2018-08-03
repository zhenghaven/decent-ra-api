#include "Enclave_t.h"
#include "SGXRAClient.h"

#include <string>

#include <sgx_tkey_exchange.h>

#include "../common_enclave/sgx_ra_tools.h"
#include "../common_enclave/EnclaveStatus.h"
#include "../common_enclave/DecentError.h"

#include "../common/CryptoTools.h"
#include "../common/sgx_ra_msg4.h"

#include "Enclave.h"

void DropServerRAState(const std::string& serverID)
{
	auto it = EnclaveState::GetInstance().GetServersMap().find(serverID);
	if (it != EnclaveState::GetInstance().GetServersMap().end())
	{
		EnclaveState::GetInstance().GetServersMap().erase(it);
	}
}

sgx_status_t ecall_init_ra_client_environment()
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	sgx_status_t res = SGX_SUCCESS;
	if (cryptoMgr.GetStatus() != SGX_SUCCESS)
	{
		return cryptoMgr.GetStatus(); //Error return. (Error from SGX)
	}

	enclave_printf("Public Sign Key: %s\n", SerializePubKey(cryptoMgr.GetSignPubKey()).c_str());
	enclave_printf("Public Encr Key: %s\n", SerializePubKey(cryptoMgr.GetEncrPubKey()).c_str());

	return SGX_SUCCESS;
}

sgx_status_t ecall_process_ra_msg0_resp(const char* ServerID, const sgx_ec256_public_t* inPubKey, int enablePSE, sgx_ra_context_t* outContextID)
{
	auto it = EnclaveState::GetInstance().GetServersMap().find(ServerID);
	if (it != EnclaveState::GetInstance().GetServersMap().end())
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg0, but client ID already exist.");
	}
	EnclaveState::GetInstance().GetServersMap().
		insert(
			std::make_pair<std::string, std::pair<ServerRAState, RAKeyManager> >(
				ServerID, 
				std::make_pair<ServerRAState, RAKeyManager>(ServerRAState::MSG0_DONE, RAKeyManager(*inPubKey))
			)
		);

	return enclave_init_ra(inPubKey, enablePSE, outContextID); //Error return. (Error from SGX)
}

sgx_status_t ecall_process_ra_msg2(const char* ServerID, sgx_ra_context_t inContextID)
{
	auto it = EnclaveState::GetInstance().GetServersMap().find(ServerID);
	if (it == EnclaveState::GetInstance().GetServersMap().end()
		|| it->second.first != ServerRAState::MSG0_DONE)
	{
		DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg2, but client ID doesn't exist or in a invalid state.");
	}

	RAKeyManager& serverKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	sgx_ra_key_128_t tmpKey;
	res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_SK, &tmpKey);
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}
	serverKeyMgr.SetSK(tmpKey);
	res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_MK, &tmpKey);
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}
	serverKeyMgr.SetMK(tmpKey);
	//res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_VK, &tmpKey);
	//if (res != SGX_SUCCESS)
	//{
	//	return res;
	//}
	//serverKeyMgr.SetVK(tmpKey);

	it->second.first = ServerRAState::MSG2_DONE;

	return SGX_SUCCESS;
}

sgx_status_t ecall_process_ra_msg4(const char* ServerID, const sgx_ra_msg4_t* inMsg4, sgx_ec256_signature_t* inMsg4Sign, sgx_ra_context_t inContextID)
{
	auto it = EnclaveState::GetInstance().GetServersMap().find(ServerID);
	if (it == EnclaveState::GetInstance().GetServersMap().end()
		|| it->second.first != ServerRAState::MSG2_DONE)
	{
		DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg4, but client ID doesn't exist or in a invalid state.");
	}

	RAKeyManager& serverKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	uint8_t signVerifyRes = 0;
	res = sgx_ecdsa_verify((uint8_t *)inMsg4, sizeof(sgx_ra_msg4_t), &(serverKeyMgr.GetSignKey()), inMsg4Sign, &signVerifyRes, EnclaveState::GetInstance().GetCryptoMgr().GetECC());
	if (signVerifyRes != SGX_EC_VALID)
	{
		DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg4, but the signature of msg 4 is invalid.");
	}
	if (inMsg4->status != ias_quote_status_t::IAS_QUOTE_OK)
	{
		DropServerRAState(ServerID);
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("Processing msg4, but the quote is rejected by the IAS.");
	}

	it->second.first = ServerRAState::ATTESTED;

	sgx_ra_close(inContextID);

	return SGX_SUCCESS;
}
