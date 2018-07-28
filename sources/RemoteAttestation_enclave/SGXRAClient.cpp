#include "Enclave_t.h"
#include "SGXRAClient.h"

#include <string>

#include <sgx_tkey_exchange.h>

#include "../common_enclave/sgx_ra_tools.h"
#include "../common_enclave/EnclaveStatus.h"

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
		return cryptoMgr.GetStatus();
	}

	enclave_printf("Public Sign Key: %s\n", SerializePubKey(cryptoMgr.GetSignPubKey()).c_str());
	enclave_printf("Public Encr Key: %s\n", SerializePubKey(cryptoMgr.GetEncrPubKey()).c_str());

	return res;
}

sgx_status_t ecall_process_ra_msg0_resp(const char* ServerID, const sgx_ec256_public_t* inPubKey, int enablePSE, sgx_ra_context_t* outContextID)
{
	auto it = EnclaveState::GetInstance().GetServersMap().find(ServerID);
	if (it != EnclaveState::GetInstance().GetServersMap().end())
	{
		return SGX_ERROR_UNEXPECTED;
	}
	EnclaveState::GetInstance().GetServersMap().
		insert(
			std::make_pair<std::string, std::pair<ServerRAState, RAKeyManager> >(
				ServerID, 
				std::make_pair<ServerRAState, RAKeyManager>(ServerRAState::MSG0_DONE, RAKeyManager(*inPubKey))
			)
		);

	return enclave_init_ra(inPubKey, enablePSE, outContextID);
}

sgx_status_t ecall_process_ra_msg2(const char* ServerID, sgx_ra_context_t inContextID)
{
	auto it = EnclaveState::GetInstance().GetServersMap().find(ServerID);
	if (it == EnclaveState::GetInstance().GetServersMap().end()
		|| it->second.first != ServerRAState::MSG0_DONE)
	{
		DropServerRAState(ServerID);
		return SGX_ERROR_UNEXPECTED;
	}

	RAKeyManager& serverKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	sgx_ra_key_128_t tmpKey;
	res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_SK, &tmpKey);
	if (res != SGX_SUCCESS)
	{
		return res;
	}
	serverKeyMgr.SetSK(tmpKey);
	res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_MK, &tmpKey);
	if (res != SGX_SUCCESS)
	{
		return res;
	}
	serverKeyMgr.SetMK(tmpKey);
	//res = sgx_ra_get_keys(inContextID, SGX_RA_KEY_VK, &tmpKey);
	//if (res != SGX_SUCCESS)
	//{
	//	return res;
	//}
	//serverKeyMgr.SetVK(tmpKey);

	it->second.first = ServerRAState::MSG2_DONE;

	return res;
}

sgx_status_t ecall_process_ra_msg4(const char* ServerID, const sgx_ra_msg4_t* inMsg4, sgx_ec256_signature_t* inMsg4Sign, sgx_ra_context_t inContextID)
{
	auto it = EnclaveState::GetInstance().GetServersMap().find(ServerID);
	if (it == EnclaveState::GetInstance().GetServersMap().end()
		|| it->second.first != ServerRAState::MSG2_DONE)
	{
		DropServerRAState(ServerID);
		return SGX_ERROR_UNEXPECTED;
	}

	RAKeyManager& serverKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	uint8_t signVerifyRes = 0;
	res = sgx_ecdsa_verify((uint8_t *)inMsg4, sizeof(sgx_ra_msg4_t), &(serverKeyMgr.GetSignKey()), inMsg4Sign, &signVerifyRes, EnclaveState::GetInstance().GetCryptoMgr().GetECC());
	if (signVerifyRes != SGX_EC_VALID)
	{
		DropServerRAState(ServerID);
		return SGX_ERROR_UNEXPECTED;
	}
	if (inMsg4->status != ias_quote_status_t::IAS_QUOTE_OK)
	{
		DropServerRAState(ServerID);
		return SGX_ERROR_UNEXPECTED;
	}

	it->second.first = ServerRAState::ATTESTED;

	sgx_ra_close(inContextID);

	//AdjustSharedKeysServ(ServerID);

	//enclave_printf("Current Skey: %s\n", SerializeKey(serverKeyMgr.GetSK()).c_str());

	return res;
}
