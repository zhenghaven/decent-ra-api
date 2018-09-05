#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "SGXRAClient.h"

#include <string>
#include <map>
#include <memory>
#include <mutex>

#include <sgx_tkey_exchange.h>

#include "sgx_ra_tools.h"
#include "sgx_tkey_exchange.h"

#include "../Common.h"

#include "../../common/DataCoding.h"
#include "../../common/GeneralKeyTypes.h"
#include "../../common/AESGCMCommLayer.h"
#include "../../common/EnclaveAsyKeyContainer.h"
#include "../../common/SGX/ias_report.h"
#include "../../common/SGX/IasReport.h"

struct RAClientContext
{
	std::unique_ptr<sgx_ec256_public_t> m_peerSignKey;
	std::unique_ptr<GeneralAES128BitKey> m_mk;
	std::unique_ptr<GeneralAES128BitKey> m_sk;
	std::unique_ptr<const CtxIdWrapper> m_sgxCtxId;
	bool m_isAttested;
	std::mutex m_mutex;

	RAClientContext(const sgx_ec256_public_t& signPub, std::unique_ptr<CtxIdWrapper>& sgxCtxId) noexcept :
		m_peerSignKey(new sgx_ec256_public_t(signPub)),
		m_mk(new GeneralAES128BitKey),
		m_sk(new GeneralAES128BitKey),
		m_isAttested(false),
		m_sgxCtxId(std::move(sgxCtxId))
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

bool SGXRAEnclave::AddNewServerRAState(const std::string& ServerID, const sgx_ec256_public_t& inPubKey, std::unique_ptr<CtxIdWrapper>& sgxCtxId)
{
	std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
	auto it = k_serversMap.find(ServerID);
	if (it != k_serversMap.cend())
	{
		//Error return. (Error caused by invalid input.)
		FUNC_ERR_Y("Processing msg0, but client ID already exist.", false);
	}
	g_serversMap.insert(std::make_pair(ServerID, std::shared_ptr<RAClientContext>(new RAClientContext(inPubKey, sgxCtxId))));

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
	return it == k_serversMap.cend() ? false : (it->second->m_isAttested);
}

static inline std::shared_ptr<RAClientContext> FetchServerCtx(const std::string& serverID)
{
	std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
	auto it = g_serversMap.find(serverID);
	return (it != g_serversMap.end()) ? (it->second) : nullptr;
}

static inline std::shared_ptr<RAClientContext> FetchAndDropServerCtx(const std::string& serverID)
{
	std::shared_ptr<RAClientContext> clientCTXPtr;
	std::lock_guard<std::mutex> mapLock(g_serversMapMutex);
	auto it = g_serversMap.find(serverID);
	if (it == g_serversMap.end())
	{
		return nullptr;
	}
	clientCTXPtr.swap(it->second);
	g_serversMap.erase(it);
	return std::move(clientCTXPtr);
}

bool SGXRAEnclave::ReleaseServerKeys(const std::string & serverID, std::unique_ptr<sgx_ec256_public_t>& outSignPubKey, std::unique_ptr<GeneralAES128BitKey>& outSK, std::unique_ptr<GeneralAES128BitKey>& outMK)
{
	std::shared_ptr<RAClientContext> clientCTXPtr(std::move(FetchAndDropServerCtx(serverID)));
	if (!clientCTXPtr)
	{
		return false;
	}

	RAClientContext& clientCTX = *clientCTXPtr;

	{
		std::lock_guard<std::mutex> ctxLock(clientCTX.m_mutex);

		outSignPubKey.swap(clientCTX.m_peerSignKey);
		outSK.swap(clientCTX.m_sk);
		outMK.swap(clientCTX.m_mk);
	}

	return true;
}

AESGCMCommLayer* SGXRAEnclave::ReleaseServerKeys(const std::string & serverID, SendFunctionType sendFunc)
{
	std::shared_ptr<RAClientContext> clientCTXPtr(std::move(FetchAndDropServerCtx(serverID)));
	if (!clientCTXPtr)
	{
		return false;
	}

	RAClientContext& clientCTX = *clientCTXPtr;
	AESGCMCommLayer* res = nullptr;
	{
		std::lock_guard<std::mutex> ctxLock(clientCTX.m_mutex);
		res = new AESGCMCommLayer(*clientCTX.m_sk, SerializeStruct(*EnclaveAsyKeyContainer::GetInstance()->GetSignPubKey()), sendFunc);
	}
	return res;
}

static inline sgx_status_t GetCommKeys(RAClientContext& clientCtx, RaGetKeyFuncType raGetKeyFuncType)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	enclaveRet = (*raGetKeyFuncType)(clientCtx.m_sgxCtxId->m_ctxId, SGX_RA_KEY_SK, reinterpret_cast<sgx_ec_key_128bit_t*>(clientCtx.m_sk->data()));
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet; //Error return. (Error from SGX)	
	}
	enclaveRet = (*raGetKeyFuncType)(clientCtx.m_sgxCtxId->m_ctxId, SGX_RA_KEY_MK, reinterpret_cast<sgx_ec_key_128bit_t*>(clientCtx.m_mk->data()));
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet; //Error return. (Error from SGX)	
	}
	return SGX_SUCCESS;
}

sgx_status_t SGXRAEnclave::ProcessRaMsg4(const std::string & serverID, const sgx_ias_report_t & inMsg4, const sgx_ec256_signature_t & inMsg4Sign, RaGetKeyFuncType raGetKeyFuncType)
{
	std::shared_ptr<RAClientContext> clientCTXPtr = FetchServerCtx(serverID);
	if (!clientCTXPtr)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	RAClientContext& clientCTX = *clientCTXPtr;
	std::lock_guard<std::mutex> ctxLock(clientCTX.m_mutex);
	if (clientCTXPtr->m_isAttested ||
		!(clientCTXPtr->m_sgxCtxId))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;

	{
		sgx_ecc_state_handle_t eccState;
		enclaveRet = sgx_ecc256_open_context(&eccState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return enclaveRet; //Error return. (Error from SGX)
		}

		uint8_t signVerifyRes = SGX_EC_INVALID_SIGNATURE;
		enclaveRet = sgx_ecdsa_verify(reinterpret_cast<const uint8_t*>(&inMsg4), sizeof(inMsg4), (clientCTX.m_peerSignKey.get()), const_cast<sgx_ec256_signature_t*>(&inMsg4Sign), &signVerifyRes, eccState);
		sgx_ecc256_close_context(eccState);

		if (enclaveRet != SGX_SUCCESS)
		{
			return enclaveRet; //Error return. (Error from SGX)
		}
		if (signVerifyRes != SGX_EC_VALID)
		{
			return SGX_ERROR_INVALID_PARAMETER;
		}
	}

	if (inMsg4.m_status != static_cast<uint8_t>(ias_quote_status_t::IAS_QUOTE_OK))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	enclaveRet = GetCommKeys(clientCTX, raGetKeyFuncType);
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	clientCTX.m_isAttested = true;
	clientCTX.m_sgxCtxId.reset();

	return SGX_SUCCESS;
}

/**
* \brief	Initialize client's Remote Attestation environment.
*
* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h . *NOTE:* The error here only comes from SGX runtime.
*/
extern "C" sgx_status_t ecall_sgx_ra_client_init()
{
	sgx_status_t res = SGX_SUCCESS;
	if (!EnclaveAsyKeyContainer::GetInstance()->IsValid())
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
extern "C" sgx_status_t ecall_get_ra_client_pub_sig_key(sgx_ec256_public_t* out_key)
{
	if (!out_key)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	std::shared_ptr<EnclaveAsyKeyContainer> keyContainer = EnclaveAsyKeyContainer::GetInstance();
	if (!keyContainer->IsValid())
	{
		return SGX_ERROR_UNEXPECTED; //Error return. (Error from SGX)
	}

	std::shared_ptr<const sgx_ec256_public_t> signPub = keyContainer->GetSignPubKey();
	std::memcpy(out_key, signPub.get(), sizeof(sgx_ec256_public_t));
	return SGX_SUCCESS;
}

extern "C" void ecall_drop_ra_state_to_server(const char* server_id)
{
	SGXRAEnclave::DropRAStateToServer(server_id);
}

extern "C" sgx_status_t ecall_process_ra_msg0_resp(const char* server_id, const sgx_ec256_public_t* in_pub_key, int enable_pse, sgx_ra_context_t* out_ctx_id)
{
	if (!server_id || !in_pub_key || !out_ctx_id)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	sgx_status_t enclaveRet = enclave_init_sgx_ra(in_pub_key, enable_pse, nullptr, out_ctx_id);
	if (enclaveRet != SGX_SUCCESS)
	{
		return enclaveRet;
	}

	std::unique_ptr<CtxIdWrapper> sgxCtxId(new CtxIdWrapper(*out_ctx_id, &sgx_ra_close));
	bool res = SGXRAEnclave::AddNewServerRAState(server_id, *in_pub_key, sgxCtxId);
	return res ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

extern "C" sgx_status_t ecall_process_ra_msg4(const char* server_id, const sgx_ias_report_t* in_msg4, sgx_ec256_signature_t* in_msg4_sign)
{
	if (!server_id || !in_msg4 || !in_msg4_sign)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGXRAEnclave::ProcessRaMsg4(server_id, *in_msg4, *in_msg4_sign, &sgx_ra_get_keys);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
