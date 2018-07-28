#include "Enclave_t.h"
#include "SGXRASP.h"

#include <string>

#include <sgx_utils.h>

#include "../common_enclave/EnclaveStatus.h"

#include "../common/CryptoTools.h"
#include "../common/sgx_crypto_tools.h"
#include "../common/sgx_constants.h"
#include "../common/sgx_ra_msg4.h"

#include "Enclave.h"

namespace
{
	sgx_spid_t sgxSPID = { {
			0xDD,
			0x16,
			0x40,
			0xFE,
			0x0D,
			0x28,
			0xC9,
			0xA8,
			0xB3,
			0x05,
			0xAF,
			0x4D,
			0x4E,
			0x76,
			0x58,
			0xBE,
		} };
	
	std::string g_selfHash = "";
}

void DropClientRAState(const std::string& clientID)
{
	auto it = EnclaveState::GetInstance().GetClientsMap().find(clientID);
	if (it != EnclaveState::GetInstance().GetClientsMap().end())
	{
		EnclaveState::GetInstance().GetClientsMap().erase(it);
	}
}

sgx_status_t ecall_init_ra_sp_environment()
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	sgx_status_t res = SGX_SUCCESS;
	if (cryptoMgr.GetStatus() != SGX_SUCCESS)
	{
		return cryptoMgr.GetStatus();
	}

	enclave_printf("Public Sign Key: %s\n", SerializePubKey(cryptoMgr.GetSignPubKey()).c_str());
	enclave_printf("Public Encr Key: %s\n", SerializePubKey(cryptoMgr.GetEncrPubKey()).c_str());

	sgx_report_t selfReport;
	res = sgx_create_report(nullptr, nullptr, &selfReport);
	if (res != SGX_SUCCESS)
	{
		return res;
	}
	sgx_measurement_t& enclaveHash = selfReport.body.mr_enclave;
	enclave_printf("Enclave Program Hash: %s\n", SerializeStruct(enclaveHash).c_str());
	g_selfHash = SerializeStruct(enclaveHash);

	return res;
}

sgx_status_t ecall_process_ra_msg0_send(const char* clientID)
{
	std::map<std::string, std::pair<ClientRAState, RAKeyManager>>& clientsMap = EnclaveState::GetInstance().GetClientsMap();
	sgx_ec256_public_t clientSignkey;
	DeserializePubKey(clientID, clientSignkey);
	auto it = clientsMap.find(clientID);
	if (it != clientsMap.end())
	{
		return SGX_ERROR_UNEXPECTED;
	}
	clientsMap.insert(std::make_pair<std::string, std::pair<ClientRAState, RAKeyManager> >(clientID, std::make_pair<ClientRAState, RAKeyManager>(ClientRAState::MSG0_DONE, RAKeyManager(clientSignkey))));

	return SGX_SUCCESS;
}

sgx_status_t ecall_process_ra_msg1(const char* clientID, const sgx_ra_msg1_t *inMsg1, sgx_ra_msg2_t *outMsg2)
{
	std::map<std::string, std::pair<ClientRAState, RAKeyManager>>& clientsMap = EnclaveState::GetInstance().GetClientsMap();
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	auto it = clientsMap.find(clientID);
	if (it == clientsMap.end()
		|| it->second.first != ClientRAState::MSG0_DONE)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;

	clientKeyMgr.SetEncryptKey((inMsg1->g_a));

	sgx_ec256_dh_shared_t sharedKey;
	res = sgx_ecc256_compute_shared_dhkey(const_cast<sgx_ec256_private_t*>(&(cryptoMgr.GetEncrPriKey())), &(clientKeyMgr.GetEncryptKey()), &sharedKey, cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}
	clientKeyMgr.SetSharedKey(sharedKey);

	sgx_ec_key_128bit_t tmpDerivedKey;
	bool keyDeriveRes = false;
	keyDeriveRes = derive_key(&(clientKeyMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_SMK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	clientKeyMgr.SetSMK(tmpDerivedKey);
	keyDeriveRes = derive_key(&(clientKeyMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_MK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	clientKeyMgr.SetMK(tmpDerivedKey);
	keyDeriveRes = derive_key(&(clientKeyMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_SK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	clientKeyMgr.SetSK(tmpDerivedKey);
	keyDeriveRes = derive_key(&(clientKeyMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_VK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	clientKeyMgr.SetVK(tmpDerivedKey);

	memcpy(&(outMsg2->g_b), &(cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t));
	memcpy(&(outMsg2->spid), &sgxSPID, sizeof(sgxSPID));
	outMsg2->quote_type = SGX_QUOTE_LINKABLE_SIGNATURE;

	outMsg2->kdf_id = SAMPLE_AES_CMAC_KDF_ID;

	sgx_ec256_public_t gb_ga[2];
	memcpy(&gb_ga[0], &(cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t));
	memcpy(&gb_ga[1], &(clientKeyMgr.GetEncryptKey()), sizeof(sgx_ec256_public_t));

	res = sgx_ecdsa_sign((uint8_t *)&gb_ga, sizeof(gb_ga), const_cast<sgx_ec256_private_t*>(&(cryptoMgr.GetSignPriKey())), &(outMsg2->sign_gb_ga), cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}
	uint8_t mac[SAMPLE_EC_MAC_SIZE] = { 0 };
	uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
	res = sgx_rijndael128_cmac_msg(reinterpret_cast<sgx_cmac_128bit_key_t*>(clientKeyMgr.GetSMK()), (uint8_t *)&(outMsg2->g_b), cmac_size, &mac);
	memcpy(&(outMsg2->mac), mac, sizeof(mac));

	outMsg2->sig_rl_size = 0;

	it->second.first = ClientRAState::MSG1_DONE;

	return res;
}

sgx_status_t ecall_process_ra_msg3(const char* clientID, const uint8_t* inMsg3, uint32_t msg3Len, const char* iasReport, const char* reportSign, sgx_ra_msg4_t* outMsg4, sgx_ec256_signature_t* outMsg4Sign)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	auto it = EnclaveState::GetInstance().GetClientsMap().find(clientID);
	if (it == EnclaveState::GetInstance().GetClientsMap().end()
		|| it->second.first != ClientRAState::MSG1_DONE)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t res = SGX_SUCCESS;
	int cmpRes = 0;
	const sgx_ra_msg3_t* msg3 = reinterpret_cast<const sgx_ra_msg3_t*>(inMsg3);

	// Compare g_a in message 3 with local g_a.
	cmpRes = std::memcmp(&(clientKeyMgr.GetEncryptKey()), &msg3->g_a, sizeof(sgx_ec256_public_t));
	if (cmpRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}

	//Make sure that msg3_size is bigger than sample_mac_t.
	uint32_t mac_size = msg3Len - sizeof(sgx_mac_t);
	const uint8_t *p_msg3_cmaced = inMsg3;
	p_msg3_cmaced += sizeof(sgx_mac_t);

	// Verify the message mac using SMK
	sgx_cmac_128bit_tag_t mac = { 0 };
	res = sgx_rijndael128_cmac_msg(&(clientKeyMgr.GetSMK()), p_msg3_cmaced, mac_size, &mac);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	// In real implementation, should use a time safe version of memcmp here,
	// in order to avoid side channel attack.
	cmpRes = std::memcmp(&(msg3->mac), mac, sizeof(mac));
	if (cmpRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}

	clientKeyMgr.SetSecProp(msg3->ps_sec_prop);

	const sgx_quote_t* p_quote = reinterpret_cast<const sgx_quote_t *>(msg3->quote);

	sgx_sha_state_handle_t sha_handle = nullptr;
	sgx_report_data_t report_data = { 0 };
	// Verify the report_data in the Quote matches the expected value.
	// The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
	// The second 32 bytes of report_data are set to zero.
	res = sgx_sha256_init(&sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(clientKeyMgr.GetEncryptKey())), sizeof(sgx_ec256_public_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(clientKeyMgr.GetVK())), sizeof(sgx_ec_key_128bit_t), sha_handle);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	res = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	cmpRes = std::memcmp((uint8_t *)&report_data, (uint8_t *)&(p_quote->report_body.report_data), sizeof(report_data));
	if (cmpRes)
	{
		DropClientRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}

	const sgx_measurement_t& enclaveHash = p_quote->report_body.mr_enclave;
	enclave_printf("Enclave Program Hash: %s\n", SerializeStruct(enclaveHash).c_str());
	if (SerializeStruct(enclaveHash) != g_selfHash)
	{
		DropClientRAState(clientID);
		enclave_printf("Program hash not matching!!\n");
		return SGX_ERROR_UNEXPECTED;
	}
	//TODO: Verify quote report here.

	//Temporary code here:
	outMsg4->id = 222;
	outMsg4->pse_status = ias_pse_status_t::IAS_PSE_OK;
	outMsg4->status = ias_quote_status_t::IAS_QUOTE_OK;

	res = sgx_ecdsa_sign((uint8_t *)outMsg4, sizeof(sgx_ra_msg4_t), const_cast<sgx_ec256_private_t*>(&(cryptoMgr.GetSignPriKey())), outMsg4Sign, cryptoMgr.GetECC());
	if (res != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		return res;
	}

	it->second.first = ClientRAState::ATTESTED;

	//AdjustSharedKeysClit(clientID);

	//enclave_printf("Current Skey: %s\n", SerializeKey(clientKeyMgr.GetSK()).c_str());

	return res;
}

