#include "Enclave_t.h"

#include "../common_enclave/enclave_tools.h"
#include "../common_enclave/EnclaveStatus.h"

#include "../common/sgx_constants.h"
#include "../common/CryptoTools.h"
#include "../common/sgx_crypto_tools.h"
#include "../common/Decent.h"

#include "SGXRAClient.h"
#include "SGXRASP.h"

namespace
{
	DecentNodeMode g_decentMode = DecentNodeMode::ROOT_SERVER;
}

static bool IsBothWayAttested(const std::string& id)
{
	auto itServ = EnclaveState::GetInstance().GetServersMap().find(id);
	auto itClit = EnclaveState::GetInstance().GetClientsMap().find(id);
	if ((itServ == EnclaveState::GetInstance().GetServersMap().end())
		|| (itClit == EnclaveState::GetInstance().GetClientsMap().end()))
	{
		return false;
	}
	if ((itClit->second.first != ClientRAState::ATTESTED)
		|| (itServ->second.first != ServerRAState::ATTESTED))
	{
		return false;
	}

	return true;
}

int ecall_adjust_shared_keys_serv(const char* id)
{
	if (!IsBothWayAttested(id))
	{
		return 0;
	}
	auto itServ = EnclaveState::GetInstance().GetServersMap().find(id);
	auto itClit = EnclaveState::GetInstance().GetClientsMap().find(id);

	itClit->second.second.SetSMK(itServ->second.second.GetSMK());
	itClit->second.second.SetSK(itServ->second.second.GetSK());
	itClit->second.second.SetMK(itServ->second.second.GetMK());
	itClit->second.second.SetVK(itServ->second.second.GetVK());

	enclave_printf("Adjusted Skey: %s\n", SerializeKey(itClit->second.second.GetSK()).c_str());
	return 1;
}

int ecall_adjust_shared_keys_clit(const char* id)
{
	if (!IsBothWayAttested(id))
	{
		return 0;
	}
	auto itServ = EnclaveState::GetInstance().GetServersMap().find(id);
	auto itClit = EnclaveState::GetInstance().GetClientsMap().find(id);

	itServ->second.second.SetSMK(itClit->second.second.GetSMK());
	itServ->second.second.SetSK(itClit->second.second.GetSK());
	itServ->second.second.SetMK(itClit->second.second.GetMK());
	itServ->second.second.SetVK(itClit->second.second.GetVK());

	enclave_printf("Adjusted Skey: %s\n", SerializeKey(itServ->second.second.GetSK()).c_str());
	return 1;
}

void ecall_set_decent_mode(DecentNodeMode inDecentMode)
{
	g_decentMode = inDecentMode;
}

DecentNodeMode ecall_get_decent_mode()
{
	return g_decentMode;
}

sgx_status_t ecall_get_protocol_sign_key(const char* clientID, sgx_ec256_private_t* outPriKey, sgx_aes_gcm_128bit_tag_t* outPriKeyMac, sgx_ec256_public_t* outPubKey, sgx_aes_gcm_128bit_tag_t* outPubKeyMac)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = EnclaveState::GetInstance().GetClientsMap().find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&cryptoMgr.GetSignPriKey()),
		sizeof(sgx_ec256_private_t),
		reinterpret_cast<uint8_t*>(outPriKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPriKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&cryptoMgr.GetSignPubKey()),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(outPubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPubKeyMac
	);

	return enclaveRes;
}

sgx_status_t ecall_get_protocol_encr_key(const char* clientID, sgx_ec256_private_t* outPriKey, sgx_aes_gcm_128bit_tag_t* outPriKeyMac, sgx_ec256_public_t* outPubKey, sgx_aes_gcm_128bit_tag_t* outPubKeyMac)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = EnclaveState::GetInstance().GetClientsMap().find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&cryptoMgr.GetEncrPriKey()),
		sizeof(sgx_ec256_private_t),
		reinterpret_cast<uint8_t*>(outPriKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPriKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&cryptoMgr.GetEncrPubKey()),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(outPubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPubKeyMac
	);

	return enclaveRes;
}

sgx_status_t ecall_set_protocol_sign_key(const char* clientID, const sgx_ec256_private_t* inPriKey, const sgx_aes_gcm_128bit_tag_t* inPriKeyMac, const sgx_ec256_public_t* inPubKey, const sgx_aes_gcm_128bit_tag_t* inPubKeyMac)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = EnclaveState::GetInstance().GetClientsMap().find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	sgx_ec256_private_t priKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inPriKey),
		sizeof(sgx_ec256_private_t),
		reinterpret_cast<uint8_t*>(&priKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inPriKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	sgx_ec256_public_t pubKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inPubKey),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(&pubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inPubKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	sgx_ec256_signature_t signSign;
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&pubKey), sizeof(sgx_ec256_public_t), &priKey, &signSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	sgx_ec256_signature_t encrSign;
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t), &priKey, &encrSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	cryptoMgr.SetSignPriKey(priKey);
	cryptoMgr.SetSignPubKey(pubKey);
	cryptoMgr.SetProtoSignPubKey(pubKey);
	cryptoMgr.SetSignKeySign(signSign);
	cryptoMgr.SetEncrKeySign(encrSign);

	enclave_printf("New Public Sign Key: %s\n", SerializePubKey(cryptoMgr.GetSignPubKey()).c_str());

	return enclaveRes;
}

sgx_status_t ecall_set_protocol_encr_key(const char* clientID, const sgx_ec256_private_t* inPriKey, const sgx_aes_gcm_128bit_tag_t* inPriKeyMac, const sgx_ec256_public_t* inPubKey, const sgx_aes_gcm_128bit_tag_t* inPubKeyMac)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = EnclaveState::GetInstance().GetClientsMap().find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	sgx_ec256_private_t priKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inPriKey),
		sizeof(sgx_ec256_private_t),
		reinterpret_cast<uint8_t*>(&priKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inPriKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	sgx_ec256_public_t pubKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inPubKey),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(&pubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inPubKeyMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	sgx_ec256_signature_t encrSign;
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&encrSign), sizeof(sgx_ec256_public_t), const_cast<sgx_ec256_private_t*>(&cryptoMgr.GetSignPriKey()), &encrSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	cryptoMgr.SetEncrPriKey(priKey);
	cryptoMgr.SetEncrPubKey(pubKey);
	cryptoMgr.SetEncrKeySign(encrSign);

	enclave_printf("New Public Encr Key: %s\n", SerializePubKey(cryptoMgr.GetEncrPubKey()).c_str());

	return enclaveRes;
}

sgx_status_t ecall_get_protocol_key_signed(const char* clientID, const sgx_ec256_public_t* inSignKey, const sgx_ec256_public_t* inEncrKey,
	sgx_ec256_signature_t* outSignSign, sgx_aes_gcm_128bit_tag_t* outSignSignMac, sgx_ec256_signature_t* outEncrSign, sgx_aes_gcm_128bit_tag_t* outEncrSignMac)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = EnclaveState::GetInstance().GetClientsMap().find(clientID);

	RAKeyManager& clientKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;
	sgx_ec256_signature_t signSign;
	sgx_ec256_signature_t encrSign;

	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(inSignKey), sizeof(sgx_ec256_public_t), const_cast<sgx_ec256_private_t*>(&cryptoMgr.GetSignPriKey()), &signSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(inEncrKey), sizeof(sgx_ec256_public_t), const_cast<sgx_ec256_private_t*>(&cryptoMgr.GetSignPriKey()), &encrSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&signSign),
		sizeof(sgx_ec256_signature_t),
		reinterpret_cast<uint8_t*>(outSignSign),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outSignSignMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	enclaveRes = sgx_rijndael128GCM_encrypt(&clientKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&encrSign),
		sizeof(sgx_ec256_signature_t),
		reinterpret_cast<uint8_t*>(outEncrSign),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outEncrSignMac
	);

	return enclaveRes;
}

sgx_status_t ecall_set_key_signs(const char* clientID, const sgx_ec256_signature_t* inSignSign, const sgx_aes_gcm_128bit_tag_t* inSignSignMac, const sgx_ec256_signature_t* inEncrSign, const sgx_aes_gcm_128bit_tag_t* inEncrSignMac)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if (g_decentMode != DecentNodeMode::APPL_SERVER)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	if (!IsBothWayAttested(clientID))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	auto it = EnclaveState::GetInstance().GetServersMap().find(clientID);

	RAKeyManager& serverKeyMgr = it->second.second;

	sgx_status_t enclaveRes = SGX_SUCCESS;
	sgx_ec256_signature_t signSign;
	sgx_ec256_signature_t encrSign;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_decrypt(&serverKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inSignSign),
		sizeof(sgx_ec256_signature_t),
		reinterpret_cast<uint8_t*>(&signSign),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inSignSignMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	enclaveRes = sgx_rijndael128GCM_decrypt(&serverKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(inEncrSign),
		sizeof(sgx_ec256_signature_t),
		reinterpret_cast<uint8_t*>(&encrSign),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		inEncrSignMac
	);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}

	cryptoMgr.SetSignKeySign(signSign);
	cryptoMgr.SetEncrKeySign(encrSign);

	cryptoMgr.SetProtoSignPubKey(serverKeyMgr.GetSignKey());
	enclave_printf("Accept Protocol Pub Sign Key: %s\n\n", SerializePubKey(cryptoMgr.GetProtoSignPubKey()).c_str());
	enclave_printf("The Signature of Sign Pub Key is: %s\n", SerializeSignature(signSign).c_str());
	enclave_printf("The Signature of Encr Pub Key is: %s\n", SerializeSignature(encrSign).c_str());

	return enclaveRes;
}

void ecall_get_key_signs(sgx_ec256_signature_t* outSignSign, sgx_ec256_signature_t* outEncrSign)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	std::memcpy(outSignSign, &cryptoMgr.GetSignKeySign(), sizeof(sgx_ec256_signature_t));
	std::memcpy(outEncrSign, &cryptoMgr.GetEncrKeySign(), sizeof(sgx_ec256_signature_t));
}

sgx_status_t ecall_proc_decent_msg0(const char* clientID, const sgx_ec256_public_t* inSignKey, const sgx_ec256_signature_t* inSignSign, const sgx_ec256_public_t* inEncrKey, const sgx_ec256_signature_t* inEncrSign)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t verifyRes = 0;
	enclaveRes = sgx_ecdsa_verify(reinterpret_cast<const uint8_t*>(inSignKey), sizeof(sgx_ec256_public_t), &cryptoMgr.GetProtoSignPubKey(), const_cast<sgx_ec256_signature_t*>(inSignSign), &verifyRes, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	if (verifyRes != SGX_EC_VALID)
	{
		enclave_printf("The signature of Attestee's Sign key is invalid.\n");
		return SGX_ERROR_UNEXPECTED;
	}

	enclaveRes = sgx_ecdsa_verify(reinterpret_cast<const uint8_t*>(inEncrKey), sizeof(sgx_ec256_public_t), &cryptoMgr.GetProtoSignPubKey(), const_cast<sgx_ec256_signature_t*>(inEncrSign), &verifyRes, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes;
	}
	if (verifyRes != SGX_EC_VALID)
	{
		enclave_printf("The signature of Attestee's Encr key is invalid.\n");
		return SGX_ERROR_UNEXPECTED;
	}

	EnclaveState::GetInstance().GetClientsMap().insert(std::make_pair<std::string, std::pair<ClientRAState, RAKeyManager> >(clientID, std::make_pair<ClientRAState, RAKeyManager>(ClientRAState::ATTESTED, RAKeyManager(*inSignKey))));
	EnclaveState::GetInstance().GetServersMap().insert(std::make_pair<std::string, std::pair<ServerRAState, RAKeyManager> >(clientID, std::make_pair<ServerRAState, RAKeyManager>(ServerRAState::ATTESTED, RAKeyManager(*inSignKey))));
	enclave_printf("Accept new app server: %s\n", clientID);

	RAKeyManager& svrMgr = EnclaveState::GetInstance().GetClientsMap().find(clientID)->second.second;
	RAKeyManager& cliMgr = EnclaveState::GetInstance().GetServersMap().find(clientID)->second.second;

	svrMgr.SetEncryptKey(*inEncrKey);
	cliMgr.SetEncryptKey(*inEncrKey);


	sgx_ec256_dh_shared_t sharedKey;
	enclaveRes = sgx_ecc256_compute_shared_dhkey(const_cast<sgx_ec256_private_t*>(&(cryptoMgr.GetEncrPriKey())), &(svrMgr.GetEncryptKey()), &sharedKey, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return enclaveRes;
	}
	svrMgr.SetSharedKey(sharedKey);
	cliMgr.SetSharedKey(sharedKey);

	sgx_ec_key_128bit_t tmpDerivedKey;
	bool keyDeriveRes = false;
	keyDeriveRes = sp_derive_key(&(svrMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_SMK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	svrMgr.SetSMK(tmpDerivedKey);
	cliMgr.SetSMK(tmpDerivedKey);

	keyDeriveRes = sp_derive_key(&(svrMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_SK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	svrMgr.SetSK(tmpDerivedKey);
	cliMgr.SetSK(tmpDerivedKey);

	keyDeriveRes = sp_derive_key(&(svrMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_MK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	svrMgr.SetMK(tmpDerivedKey);
	cliMgr.SetMK(tmpDerivedKey);

	keyDeriveRes = sp_derive_key(&(svrMgr.GetSharedKey()), SAMPLE_DERIVE_KEY_VK, &tmpDerivedKey);
	if (!keyDeriveRes)
	{
		DropClientRAState(clientID);
		DropServerRAState(clientID);
		return SGX_ERROR_UNEXPECTED;
	}
	svrMgr.SetVK(tmpDerivedKey);
	cliMgr.SetVK(tmpDerivedKey);

	return enclaveRes;
}
