#include "SGXRADecent.h"

#include <string>
#include <map>

#include <openssl/ec.h>

#include <sgx_utils.h>

#include "../common_enclave/DecentError.h"

#include "../common/CommonTool.h"
#include "../common/EnclaveRAState.h"
#include "../common/CryptoTools.h"
#include "../common/Decent.h"
#include "../common/RAKeyManager.h"
#include "../common/SGX/sgx_constants.h"
#include "../common/SGX/sgx_crypto_tools.h"
#include "../common/SGX/SGXRAServiceProvider.h"
#include "../common/SGX/SGXOpenSSLConversions.h"
#include "../common/OpenSSLTools.h"

#include "sgx_ra_tools.h"
#include "SGXRAClient.h"

namespace
{
	static DecentNodeMode g_decentMode = DecentNodeMode::ROOT_SERVER;
	static std::map<std::string, RAKeyManager> g_decentNodesMap;

	//Shared objects:
	static RACryptoManager& g_cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
}

static bool IsBothWayAttested(const std::string& id)
{
	bool isClientAttested = SGXRAEnclave::IsClientAttested(id);
	bool isServerAttested = SGXRAEnclave::IsServerAttested(id);

	return isClientAttested && isServerAttested;
}

bool DecentEnclave::IsAttested(const std::string& id)
{
	return g_decentNodesMap.find(id) != g_decentNodesMap.end();
}

const RAKeyManager * DecentEnclave::GetNodeKeyMgr(const std::string& id)
{
	auto it = g_decentNodesMap.find(id);
	return it == g_decentNodesMap.end() ? nullptr : (&it->second);
}

extern "C" sgx_status_t ecall_init_decent_ra_environment(const sgx_spid_t* inSpid)
{
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

extern "C" sgx_status_t ecall_transit_to_decent_node(const char* id, int is_server)
{
	if (!IsBothWayAttested(id))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	if (is_server) 
	{
		g_decentNodesMap.insert(std::make_pair(id, *SGXRAEnclave::GetClientKeysMgr(id)));
	}
	else
	{
		g_decentNodesMap.insert(std::make_pair(id, *SGXRAEnclave::GetServerKeysMgr(id)));
	}

	return SGX_SUCCESS;
}

extern "C" void ecall_set_decent_mode(DecentNodeMode inDecentMode)
{
	g_decentMode = inDecentMode;
}

extern "C" DecentNodeMode ecall_get_decent_mode()
{
	return g_decentMode;
}

extern "C" sgx_status_t ecall_process_ra_msg0_send_decent(const char* clientID)
{
	if (!clientID)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	//std::map<std::string, std::pair<ClientRAState, RAKeyManager>>& clientsMap = EnclaveState::GetInstance().GetClientsMap();
	sgx_ec256_public_t clientSignkey;
	DeserializePubKey(clientID, clientSignkey);
	if (!SGXRAEnclave::AddNewClientRAState(clientID, clientSignkey))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	ReportDataVerifier reportDataVerifier = [clientSignkey](const uint8_t* initData, const std::vector<uint8_t>& inData) -> bool
	{
		EC_KEY* pubKey = EC_KEY_new();
		if (!pubKey || !ECKeyPubSGX2OpenSSL(&clientSignkey, pubKey, nullptr))
		{
			EC_KEY_free(pubKey);
			return false;
		}
		std::string pubKeyPem = ECKeyPubGetPEMStr(pubKey);
		EC_KEY_free(pubKey);
		if (pubKeyPem.size() == 0)
		{
			return false;
		}

		COMMON_PRINTF("Verifying report data with Public Key:\n%s\n", pubKeyPem.c_str());
		sgx_sha_state_handle_t shaState;
		sgx_sha256_hash_t tmpHash;
		sgx_status_t enclaveRet = sgx_sha256_init(&shaState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return false;
		}
		enclaveRet = sgx_sha256_update(initData, SGX_SHA256_HASH_SIZE / 2, shaState);
		if (enclaveRet != SGX_SUCCESS)
		{
			sgx_sha256_close(shaState);
			return false;
		}
		enclaveRet = sgx_sha256_update(reinterpret_cast<const uint8_t*>(pubKeyPem.data()), static_cast<uint32_t>(pubKeyPem.size()), shaState);
		if (enclaveRet != SGX_SUCCESS)
		{
			sgx_sha256_close(shaState);
			return false;
		}
		enclaveRet = sgx_sha256_get_hash(shaState, &tmpHash);
		if (enclaveRet != SGX_SUCCESS)
		{
			sgx_sha256_close(shaState);
			return false;
		}
		sgx_sha256_close(shaState);

		return std::memcmp(tmpHash, inData.data(), inData.size()) == 0;
	};

	SGXRAEnclave::SetReportDataVerifier(clientID, reportDataVerifier); //Imposible to return false on this call.

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_process_ra_msg0_resp_decent(const char* ServerID, const sgx_ec256_public_t* inPubKey, int enablePSE, sgx_ra_context_t* outContextID)
{
	if (!ServerID || !inPubKey || !outContextID ||
		!SGXRAEnclave::AddNewServerRAState(ServerID, *inPubKey))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	ReportDataGenerator rdGenerator = [](const uint8_t* initData, std::vector<uint8_t>& outData, const size_t inLen) -> bool
	{
		EC_KEY* pubKey = EC_KEY_new();
		if (!pubKey || !ECKeyPubSGX2OpenSSL(&g_cryptoMgr.GetSignPubKey(), pubKey, nullptr))
		{
			EC_KEY_free(pubKey);
			return false;
		}
		std::string pubKeyPem = ECKeyPubGetPEMStr(pubKey);
		EC_KEY_free(pubKey);
		if (pubKeyPem.size() == 0)
		{
			return false;
		}

		COMMON_PRINTF("Generating report data with Public Key:\n%s\n", pubKeyPem.c_str());
		sgx_sha_state_handle_t shaState;
		sgx_status_t enclaveRet = sgx_sha256_init(&shaState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return false;
		}
		enclaveRet = sgx_sha256_update(initData, SGX_SHA256_HASH_SIZE / 2, shaState);
		if (enclaveRet != SGX_SUCCESS)
		{
			sgx_sha256_close(shaState);
			return false;
		}
		enclaveRet = sgx_sha256_update(reinterpret_cast<const uint8_t*>(pubKeyPem.data()), static_cast<uint32_t>(pubKeyPem.size()), shaState);
		if (enclaveRet != SGX_SUCCESS)
		{
			sgx_sha256_close(shaState);
			return false;
		}
		outData.resize(SGX_SHA256_HASH_SIZE, 0);
		enclaveRet = sgx_sha256_get_hash(shaState, reinterpret_cast<sgx_sha256_hash_t*>(outData.data()));
		if (enclaveRet != SGX_SUCCESS)
		{
			sgx_sha256_close(shaState);
			return false;
		}
		sgx_sha256_close(shaState);

		return true;
	};

	return enclave_init_decent_ra(inPubKey, enablePSE, rdGenerator, nullptr, outContextID); //Error return. (Error from SGX)
}

extern "C" sgx_status_t ecall_get_protocol_sign_key(const char* clientID, sgx_ec256_private_t* outPriKey, sgx_aes_gcm_128bit_tag_t* outPriKeyMac, sgx_ec256_public_t* outPubKey, sgx_aes_gcm_128bit_tag_t* outPubKeyMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("This decent node is not a Root Server!");
	}

	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if ((!clientID || !outPriKey || !outPriKeyMac || !outPubKey || !outPubKeyMac))
	{
		FUNC_ERR_Y("Invalid parameters!", SGX_ERROR_INVALID_PARAMETER);
	}
	auto nodeIt = g_decentNodesMap.find(clientID);
	if (nodeIt == g_decentNodesMap.end())
	{
		FUNC_ERR_Y("The requesting node had not been RAed.!", SGX_ERROR_INVALID_PARAMETER);
	}

	RAKeyManager& nodeKeyMgr = nodeIt->second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&nodeKeyMgr.GetSK(),
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
		return enclaveRes; //Error return. (Error from SGX)
	}

	enclaveRes = sgx_rijndael128GCM_encrypt(&nodeKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&cryptoMgr.GetSignPubKey()),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(outPubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPubKeyMac
	);

	return enclaveRes; //Error return. (Error from SGX)
}

extern "C" sgx_status_t ecall_get_protocol_encr_key(const char* clientID, sgx_ec256_private_t* outPriKey, sgx_aes_gcm_128bit_tag_t* outPriKeyMac, sgx_ec256_public_t* outPubKey, sgx_aes_gcm_128bit_tag_t* outPubKeyMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("This decent node is not a Root Server!");
	}

	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if ((!clientID || !outPriKey || !outPriKeyMac || !outPubKey || !outPubKeyMac))
	{
		FUNC_ERR_Y("Invalid parameters!", SGX_ERROR_INVALID_PARAMETER);
	}
	auto nodeIt = g_decentNodesMap.find(clientID);
	if (nodeIt == g_decentNodesMap.end())
	{
		FUNC_ERR_Y("The requesting node had not been RAed.!", SGX_ERROR_INVALID_PARAMETER);
	}

	RAKeyManager& nodeKeyMgr = nodeIt->second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&nodeKeyMgr.GetSK(),
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
		return enclaveRes; //Error return. (Error from SGX)
	}

	enclaveRes = sgx_rijndael128GCM_encrypt(&nodeKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&cryptoMgr.GetEncrPubKey()),
		sizeof(sgx_ec256_public_t),
		reinterpret_cast<uint8_t*>(outPubKey),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outPubKeyMac
	);

	return enclaveRes; //Error return. (Error from SGX)
}

extern "C" sgx_status_t ecall_set_protocol_sign_key(const char* clientID, const sgx_ec256_private_t* inPriKey, const sgx_aes_gcm_128bit_tag_t* inPriKeyMac, const sgx_ec256_public_t* inPubKey, const sgx_aes_gcm_128bit_tag_t* inPubKeyMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("This decent node is not a Root Server!");
	}

	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if ((!clientID || !inPriKey || !inPriKeyMac || !inPubKey || !inPubKeyMac))
	{
		FUNC_ERR_Y("Invalid parameters!", SGX_ERROR_INVALID_PARAMETER);
	}
	auto nodeIt = g_decentNodesMap.find(clientID);
	if (nodeIt == g_decentNodesMap.end())
	{
		FUNC_ERR_Y("The requesting node had not been RAed.!", SGX_ERROR_INVALID_PARAMETER);
	}

	RAKeyManager& nodeKeyMgr = nodeIt->second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	sgx_ec256_private_t priKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&nodeKeyMgr.GetSK(),
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
		return enclaveRes; //Error return. (Error from SGX)
	}
	sgx_ec256_public_t pubKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&nodeKeyMgr.GetSK(),
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
		return enclaveRes; //Error return. (Error from SGX)
	}

	sgx_ec256_signature_t signSign;
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&pubKey), sizeof(sgx_ec256_public_t), &priKey, &signSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes; //Error return. (Error from SGX)
	}

	sgx_ec256_signature_t encrSign;
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&cryptoMgr.GetEncrPubKey()), sizeof(sgx_ec256_public_t), &priKey, &encrSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes; //Error return. (Error from SGX)
	}

	cryptoMgr.SetSignPriKey(priKey);
	cryptoMgr.SetSignPubKey(pubKey);
	cryptoMgr.SetProtoSignPubKey(pubKey);
	cryptoMgr.SetSignKeySign(signSign);
	cryptoMgr.SetEncrKeySign(encrSign);

	ocall_printf("New Public Sign Key: %s\n", SerializePubKey(cryptoMgr.GetSignPubKey()).c_str());

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_set_protocol_encr_key(const char* clientID, const sgx_ec256_private_t* inPriKey, const sgx_aes_gcm_128bit_tag_t* inPriKeyMac, const sgx_ec256_public_t* inPubKey, const sgx_aes_gcm_128bit_tag_t* inPubKeyMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("This decent node is not a Root Server!");
	}

	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if ((!clientID || !inPriKey || !inPriKeyMac || !inPubKey || !inPubKeyMac))
	{
		FUNC_ERR_Y("Invalid parameters!", SGX_ERROR_INVALID_PARAMETER);
	}
	auto nodeIt = g_decentNodesMap.find(clientID);
	if (nodeIt == g_decentNodesMap.end())
	{
		FUNC_ERR_Y("The requesting node had not been RAed.!", SGX_ERROR_INVALID_PARAMETER);
	}

	RAKeyManager& nodeKeyMgr = nodeIt->second;

	sgx_status_t enclaveRes = SGX_SUCCESS;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	sgx_ec256_private_t priKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&nodeKeyMgr.GetSK(),
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
		return enclaveRes; //Error return. (Error from SGX)
	}

	sgx_ec256_public_t pubKey;
	enclaveRes = sgx_rijndael128GCM_decrypt(&nodeKeyMgr.GetSK(),
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
		return enclaveRes; //Error return. (Error from SGX)
	}

	sgx_ec256_signature_t encrSign;
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&encrSign), sizeof(sgx_ec256_public_t), const_cast<sgx_ec256_private_t*>(&cryptoMgr.GetSignPriKey()), &encrSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes; //Error return. (Error from SGX)
	}

	cryptoMgr.SetEncrPriKey(priKey);
	cryptoMgr.SetEncrPubKey(pubKey);
	cryptoMgr.SetEncrKeySign(encrSign);

	ocall_printf("New Public Encr Key: %s\n", SerializePubKey(cryptoMgr.GetEncrPubKey()).c_str());

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_get_protocol_key_signed(const char* clientID, const sgx_ec256_public_t* inSignKey, const sgx_ec256_public_t* inEncrKey,
	sgx_ec256_signature_t* outSignSign, sgx_aes_gcm_128bit_tag_t* outSignSignMac, sgx_ec256_signature_t* outEncrSign, sgx_aes_gcm_128bit_tag_t* outEncrSignMac)
{
	if (g_decentMode != DecentNodeMode::ROOT_SERVER)
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("This decent node is not a Root Server!");
	}

	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if ((!clientID || !inSignKey || !inEncrKey || !outSignSign || !outSignSignMac || !outEncrSign || !outEncrSignMac))
	{
		FUNC_ERR_Y("Invalid parameters!", SGX_ERROR_INVALID_PARAMETER);
	}
	auto nodeIt = g_decentNodesMap.find(clientID);
	if (nodeIt == g_decentNodesMap.end())
	{
		FUNC_ERR_Y("The requesting node had not been RAed.!", SGX_ERROR_INVALID_PARAMETER);
	}

	RAKeyManager& nodeKeyMgr = nodeIt->second;

	sgx_status_t enclaveRes = SGX_SUCCESS;
	sgx_ec256_signature_t signSign;
	sgx_ec256_signature_t encrSign;

	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(inSignKey), sizeof(sgx_ec256_public_t), const_cast<sgx_ec256_private_t*>(&cryptoMgr.GetSignPriKey()), &signSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes; //Error return. (Error from SGX)
	}
	enclaveRes = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(inEncrKey), sizeof(sgx_ec256_public_t), const_cast<sgx_ec256_private_t*>(&cryptoMgr.GetSignPriKey()), &encrSign, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes; //Error return. (Error from SGX)
	}

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_encrypt(&nodeKeyMgr.GetSK(),
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
		return enclaveRes; //Error return. (Error from SGX)
	}

	enclaveRes = sgx_rijndael128GCM_encrypt(&nodeKeyMgr.GetSK(),
		reinterpret_cast<const uint8_t*>(&encrSign),
		sizeof(sgx_ec256_signature_t),
		reinterpret_cast<uint8_t*>(outEncrSign),
		aes_gcm_iv,
		SAMPLE_SP_IV_SIZE,
		nullptr,
		0,
		outEncrSignMac
	);

	return SGX_SUCCESS;
}

extern "C" sgx_status_t ecall_set_key_signs(const char* clientID, const sgx_ec256_signature_t* inSignSign, const sgx_aes_gcm_128bit_tag_t* inSignSignMac, const sgx_ec256_signature_t* inEncrSign, const sgx_aes_gcm_128bit_tag_t* inEncrSignMac)
{
	if (g_decentMode != DecentNodeMode::APPL_SERVER)
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("This decent node is not a Root Server!");
	}

	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	if ((!clientID || !inSignSign || !inSignSignMac || !inEncrSign || !inEncrSignMac))
	{
		FUNC_ERR_Y("Invalid parameters!", SGX_ERROR_INVALID_PARAMETER);
	}
	auto nodeIt = g_decentNodesMap.find(clientID);
	if (nodeIt == g_decentNodesMap.end())
	{
		FUNC_ERR_Y("The requesting node had not been RAed.!", SGX_ERROR_INVALID_PARAMETER);
	}

	RAKeyManager& nodeKeyMgr = nodeIt->second;

	sgx_status_t enclaveRes = SGX_SUCCESS;
	sgx_ec256_signature_t signSign;
	sgx_ec256_signature_t encrSign;

	uint8_t aes_gcm_iv[SAMPLE_SP_IV_SIZE] = { 0 };
	enclaveRes = sgx_rijndael128GCM_decrypt(&nodeKeyMgr.GetSK(),
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
		return enclaveRes; //Error return. (Error from SGX)
	}
	enclaveRes = sgx_rijndael128GCM_decrypt(&nodeKeyMgr.GetSK(),
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
		return enclaveRes; //Error return. (Error from SGX)
	}

	cryptoMgr.SetSignKeySign(signSign);
	cryptoMgr.SetEncrKeySign(encrSign);

	cryptoMgr.SetProtoSignPubKey(nodeKeyMgr.GetSignKey());
	ocall_printf("Accept Protocol Pub Sign Key: %s\n\n", SerializePubKey(cryptoMgr.GetProtoSignPubKey()).c_str());
	ocall_printf("The Signature of Sign Pub Key is: %s\n", SerializeSignature(signSign).c_str());
	ocall_printf("The Signature of Encr Pub Key is: %s\n", SerializeSignature(encrSign).c_str());

	return SGX_SUCCESS;
}

extern "C" void ecall_get_key_signs(sgx_ec256_signature_t* outSignSign, sgx_ec256_signature_t* outEncrSign)
{
	if (!outSignSign || !outEncrSign)
	{
		return;
	}
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	std::memcpy(outSignSign, &cryptoMgr.GetSignKeySign(), sizeof(sgx_ec256_signature_t));
	std::memcpy(outEncrSign, &cryptoMgr.GetEncrKeySign(), sizeof(sgx_ec256_signature_t));
}

extern "C" sgx_status_t ecall_proc_decent_msg0(const char* clientID, const sgx_ec256_public_t* inSignKey, const sgx_ec256_signature_t* inSignSign, const sgx_ec256_public_t* inEncrKey, const sgx_ec256_signature_t* inEncrSign)
{
	DecentCryptoManager& cryptoMgr = EnclaveState::GetInstance().GetCryptoMgr();
	sgx_status_t enclaveRes = SGX_SUCCESS;
	int isPointValid = 0;
	if ((!clientID || !inSignKey || !inSignSign || !inEncrKey || !inEncrSign) ||
		g_decentNodesMap.find(clientID) != g_decentNodesMap.end())
	{
		FUNC_ERR_Y("Invalid parameters!", SGX_ERROR_INVALID_PARAMETER);
	}
	enclaveRes = sgx_ecc256_check_point(inSignKey, cryptoMgr.GetECC(), &isPointValid);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes; //Error return. (Error from SGX)
	}
	if (isPointValid == 0)
	{
		FUNC_ERR_Y("Invalid Signing Key!", SGX_ERROR_INVALID_PARAMETER);
	}
	enclaveRes = sgx_ecc256_check_point(inEncrKey, cryptoMgr.GetECC(), &isPointValid);
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes; //Error return. (Error from SGX)
	}
	if (isPointValid == 0)
	{
		FUNC_ERR_Y("Invalid Encryption key!", SGX_ERROR_INVALID_PARAMETER);
	}

	uint8_t verifyRes = 0;
	enclaveRes = sgx_ecdsa_verify(reinterpret_cast<const uint8_t*>(inSignKey), sizeof(sgx_ec256_public_t), &cryptoMgr.GetProtoSignPubKey(), const_cast<sgx_ec256_signature_t*>(inSignSign), &verifyRes, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes; //Error return. (Error from SGX)
	}
	if (verifyRes != SGX_EC_VALID)
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("The signature of Attestee's Sign key is invalid.");
	}

	enclaveRes = sgx_ecdsa_verify(reinterpret_cast<const uint8_t*>(inEncrKey), sizeof(sgx_ec256_public_t), &cryptoMgr.GetProtoSignPubKey(), const_cast<sgx_ec256_signature_t*>(inEncrSign), &verifyRes, cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		return enclaveRes; //Error return. (Error from SGX)
	}
	if (verifyRes != SGX_EC_VALID)
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR("The signature of Attestee's Encr key is invalid.");
	}

	auto insertRes = g_decentNodesMap.insert(std::make_pair<std::string, RAKeyManager>(clientID, RAKeyManager(*inSignKey)));
	ocall_printf("Accepted new app server: %s\n", clientID);

	RAKeyManager& nodeKeyMgr = insertRes.first->second;

	nodeKeyMgr.SetEncryptKey(*inEncrKey);

	enclaveRes = nodeKeyMgr.GenerateSharedKeySet(cryptoMgr.GetEncrPriKey(), cryptoMgr.GetECC());
	if (enclaveRes != SGX_SUCCESS)
	{
		g_decentNodesMap.erase(insertRes.first);
		return enclaveRes; //Error return. (Error from SGX)
	}

	return SGX_SUCCESS;
}
