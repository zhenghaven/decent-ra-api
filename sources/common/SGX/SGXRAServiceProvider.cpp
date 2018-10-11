#include "SGXRAServiceProvider.h"

#include <cstdlib>
#include <string>
#include <map>
#include <memory>
#include <atomic>
#include <mutex>

#include <sgx_quote.h>
#include <sgx_key_exchange.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "SGXOpenSSLConversions.h"

#include "../JsonTools.h"
#include "../CommonTool.h"
#include "../DataCoding.h"
#include "../MbedTlsObjects.h"
#include "../MbedTlsHelpers.h"
#include "../NonceGenerator.h"
#include "../AESGCMCommLayer.h"
#include "../GeneralKeyTypes.h"
#include "../CryptoKeyContainer.h"

#include "../SGX/ias_report_cert.h"
#include "../SGX/sgx_crypto_tools.h"
#include "../SGX/sgx_constants.h"
#include "../SGX/ias_report.h"
#include "../SGX/IasReport.h"

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif

enum class ClientRAState
{
	MSG0_DONE,
	MSG1_DONE,
	ATTESTED, //MSG3_DONE,
};

struct RASPContext
{
	std::shared_ptr<const general_secp256r1_public_t> m_mySignPub;
	std::shared_ptr<const PrivateKeyWrap> m_mySignPrv;
	std::unique_ptr<sgx_ec256_public_t> m_peerSignKey;

	sgx_ec256_private_t m_prvKey;

	//Do not move the following members:
	sgx_ec256_public_t m_pubKey;
	sgx_ec256_public_t m_peerEncrKey;
	//End Do Not Move.

	std::string m_nonce;
	ReportDataVerifier m_reportDataVerifier;
	sgx_ec256_dh_shared_t m_sharedKey;
	sgx_ec_key_128bit_t m_smk = { 0 };
	std::unique_ptr<GeneralAES128BitKey> m_mk;
	std::unique_ptr<GeneralAES128BitKey> m_sk;
	sgx_ec_key_128bit_t m_vk = { 0 };
	//sgx_ps_sec_prop_desc_t m_secProp;
	ClientRAState m_state;
	std::mutex m_mutex;
	std::unique_ptr<sgx_ias_report_t> m_iasReport;

	RASPContext(const CryptoKeyContainer& keyContainer, const sgx_ec256_public_t& inSignPubKey) :
		m_mySignPub(keyContainer.GetSignPubKey()),
		m_mySignPrv(keyContainer.GetSignPrvKey()),
		m_peerSignKey(new sgx_ec256_public_t),
		m_nonce(GenNonceForIASJson(IAS_REQUEST_NONCE_SIZE)),
		m_sharedKey({ {0} }),
		m_mk(new GeneralAES128BitKey),
		m_sk(new GeneralAES128BitKey),
		//m_secProp({ {0} }),
		m_state(ClientRAState::MSG0_DONE),
		m_iasReport(new sgx_ias_report_t)
	{
		m_reportDataVerifier = [](const uint8_t* initData, const std::vector<uint8_t>& inData) -> bool
		{
			return consttime_memequal(initData, inData.data(), inData.size()) == 1;
		};
	}

	sgx_status_t SetEncrPubKey(const sgx_ec256_public_t& inEncrPubKey)
	{
		std::memcpy(&m_peerEncrKey, &inEncrPubKey, sizeof(sgx_ec256_public_t));

		sgx_ecc_state_handle_t ecState;
		sgx_status_t enclaveRet = sgx_ecc256_open_context(&ecState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return enclaveRet;
		}
		enclaveRet = sgx_ecc256_compute_shared_dhkey(&m_prvKey, &m_peerEncrKey, &m_sharedKey, ecState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return enclaveRet;
		}
		sgx_ecc256_close_context(ecState);

		enclaveRet = derive_key_set(&m_sharedKey, &m_smk, reinterpret_cast<sgx_ec_key_128bit_t*>(m_mk->data()), reinterpret_cast<sgx_ec_key_128bit_t*>(m_sk->data()), &m_vk);
		return enclaveRet;
	}
};

typedef std::map<std::string, std::shared_ptr<RASPContext> > ClientsMapType;

namespace
{
	//Assume this is set correctly during init and no change afterwards.
	static std::shared_ptr<const sgx_spid_t> g_sgxSPID = std::make_shared<const sgx_spid_t>();

	std::mutex g_clientsMapMutex;
	static ClientsMapType g_clientsMap;
	static const ClientsMapType& k_clientsMap = g_clientsMap;
}

static inline std::shared_ptr<RASPContext> ConstructSpCtx(const std::string& clientID, const sgx_ec256_public_t& inPubKey)
{
	std::shared_ptr<RASPContext> spCTX(new RASPContext(CryptoKeyContainer::GetInstance(), inPubKey));
	sgx_ecc_state_handle_t ecState;
	sgx_status_t enclaveRet = sgx_ecc256_open_context(&ecState);
	if (!spCTX || (enclaveRet != SGX_SUCCESS))
	{
		sgx_ecc256_close_context(ecState);
		return nullptr;
	}
	enclaveRet = sgx_ecc256_create_key_pair(&spCTX->m_prvKey, &spCTX->m_pubKey, ecState);
	sgx_ecc256_close_context(ecState);
	if (enclaveRet != SGX_SUCCESS)
	{
		return nullptr;
	}
	return std::move(spCTX);
}

static inline bool AddNewClientRAState(const std::string& clientID, std::shared_ptr<RASPContext> spCTX)
{
	std::lock_guard<std::mutex> mapLock(g_clientsMapMutex);
	auto it = g_clientsMap.find(clientID);
	if (it != g_clientsMap.end())
	{
		return false;
	}
	g_clientsMap.insert(std::make_pair<const std::string&, std::shared_ptr<RASPContext>>(clientID, std::move(spCTX)));

	return true;
}

static inline std::shared_ptr<RASPContext> FetchSpCtx(const std::string& clientId)
{
	std::lock_guard<std::mutex> mapLock(g_clientsMapMutex);
	auto it = g_clientsMap.find(clientId);
	return (it != g_clientsMap.end()) ? it->second : nullptr;
}

bool SGXRAEnclave::SetReportDataVerifier(const std::string & clientID, ReportDataVerifier func)
{
	std::shared_ptr<RASPContext> spCTXPtr(FetchSpCtx(clientID));
	if (!spCTXPtr)
	{
		return false;
	}

	std::lock_guard<std::mutex> ctxLock(spCTXPtr->m_mutex);
	spCTXPtr->m_reportDataVerifier = func;

	return true;
}

void SGXRAEnclave::DropClientRAState(const std::string & clientID)
{
	std::lock_guard<std::mutex> mapLock(g_clientsMapMutex);
	auto it = g_clientsMap.find(clientID);
	if (it != g_clientsMap.end())
	{
		g_clientsMap.erase(it);
	}
}

bool SGXRAEnclave::IsClientAttested(const std::string & clientID)
{
	std::lock_guard<std::mutex> mapLock(g_clientsMapMutex);
	ClientsMapType::const_iterator it = k_clientsMap.find(clientID);
	return it == k_clientsMap.cend() ? false : (it->second->m_state == ClientRAState::ATTESTED);
}

bool SGXRAEnclave::ReleaseClientKeys(const std::string & clientID, std::unique_ptr<sgx_ias_report_t>& outIasReport, std::unique_ptr<sgx_ec256_public_t>& outSignPubKey, std::unique_ptr<GeneralAES128BitKey>& outSK, std::unique_ptr<GeneralAES128BitKey>& outMK)
{
	std::shared_ptr<RASPContext> spCTXPtr(FetchSpCtx(clientID));
	if (!spCTXPtr || spCTXPtr->m_state != ClientRAState::ATTESTED)
	{
		return false;
	}

	RASPContext& spCTX = *spCTXPtr;
	{
		std::lock_guard<std::mutex> ctxLock(spCTX.m_mutex);

		outIasReport.swap(spCTX.m_iasReport);
		outSignPubKey.swap(spCTX.m_peerSignKey);
		outSK.swap(spCTX.m_sk);
		outMK.swap(spCTX.m_mk);
	}

	SGXRAEnclave::DropClientRAState(clientID);

	return true;
}

AESGCMCommLayer* SGXRAEnclave::ReleaseClientKeys(const std::string & clientID, std::unique_ptr<sgx_ias_report_t>& outIasReport)
{
	std::shared_ptr<RASPContext> spCTXPtr(FetchSpCtx(clientID));
	if (!spCTXPtr || spCTXPtr->m_state != ClientRAState::ATTESTED)
	{
		return false;
	}

	AESGCMCommLayer* res = nullptr;
	RASPContext& spCTX = *spCTXPtr;
	{
		std::lock_guard<std::mutex> ctxLock(spCTX.m_mutex);

		outIasReport.swap(spCTX.m_iasReport);

		res = new AESGCMCommLayer(*spCTX.m_sk);
	}
	SGXRAEnclave::DropClientRAState(clientID);
	return res;
}

void SGXRAEnclave::SetSPID(const sgx_spid_t & spid)
{
	std::shared_ptr<const sgx_spid_t> tmpSPID = std::make_shared<const sgx_spid_t>(spid);

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::atomic_store(&g_sgxSPID, tmpSPID);
#else
	g_sgxSPID = tmpSPID;
#endif // DECENT_THREAD_SAFETY_HIGH
}

sgx_status_t SGXRAEnclave::ServiceProviderInit()
{
	sgx_status_t res = SGX_SUCCESS;
	if (!CryptoKeyContainer::GetInstance())
	{
		return SGX_ERROR_UNEXPECTED; //Error return. (Error from SGX)
	}

	return SGX_SUCCESS;
}

void SGXRAEnclave::ServiceProviderTerminate()
{
}

sgx_status_t SGXRAEnclave::GetIasNonce(const std::string& clientId, char* outStr)
{
	if (!outStr)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::shared_ptr<RASPContext> spCTXPtr(FetchSpCtx(clientId));
	if (!spCTXPtr)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::lock_guard<std::mutex> ctxLock(spCTXPtr->m_mutex);
	const std::string& res = spCTXPtr->m_nonce;
	std::memcpy(outStr, res.data(), res.size());

	return SGX_SUCCESS;
}

sgx_status_t SGXRAEnclave::GetRASPSignPubKey(sgx_ec256_public_t& outKey)
{
	CryptoKeyContainer& keyContainer = CryptoKeyContainer::GetInstance();
	if (!keyContainer)
	{
		return SGX_ERROR_UNEXPECTED; //Error return. (Error from SGX)
	}

	std::shared_ptr<const general_secp256r1_public_t> signPub(keyContainer.GetSignPubKey());
	std::memcpy(&outKey, signPub.get(), sizeof(sgx_ec256_public_t));
	return SGX_SUCCESS;
}

sgx_status_t SGXRAEnclave::ProcessRaMsg1(const std::string& clientId, const sgx_ec256_public_t& inKey, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2)
{
	std::shared_ptr<RASPContext> spCTXPtr(std::move(ConstructSpCtx(clientId, inKey)));
	if (!spCTXPtr)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	RASPContext& spCTX = *spCTXPtr;

	sgx_status_t res = SGX_SUCCESS;

	res = spCTX.SetEncrPubKey(inMsg1.g_a);
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}

	memcpy(&(outMsg2.g_b), &(spCTX.m_pubKey), sizeof(sgx_ec256_public_t));

#ifdef DECENT_THREAD_SAFETY_HIGH
	std::shared_ptr<const sgx_spid_t> tmpSPID = std::atomic_load(&g_sgxSPID);
#else
	std::shared_ptr<const sgx_spid_t> tmpSPID = g_sgxSPID;
#endif // DECENT_THREAD_SAFETY_HIGH

	memcpy(&(outMsg2.spid), tmpSPID.get(), sizeof(sgx_spid_t));
	/*TODO: Add switch for quote_type */
	outMsg2.quote_type = SGX_QUOTE_LINKABLE_SIGNATURE;
	
	outMsg2.kdf_id = SAMPLE_AES_CMAC_KDF_ID;

	{
		sgx_ecc_state_handle_t eccState;
		res = sgx_ecc256_open_context(&eccState);
		if (res != SGX_SUCCESS)
		{
			return res; //Error return. (Error from SGX)
		}
		res = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&spCTX.m_pubKey), 2 * sizeof(sgx_ec256_public_t), 
			const_cast<sgx_ec256_private_t*>(GeneralEc256Type2Sgx(&(spCTX.m_mySignPrv->m_prvKey))), &(outMsg2.sign_gb_ga), eccState);
		if (res != SGX_SUCCESS)
		{
			return res; //Error return. (Error from SGX)
		}
		sgx_ecc256_close_context(eccState);
	}

	uint8_t mac[SGX_CMAC_MAC_SIZE] = { 0 };
	uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
	res = sgx_rijndael128_cmac_msg(reinterpret_cast<sgx_cmac_128bit_key_t*>(&(spCTX.m_smk)), reinterpret_cast<uint8_t*>(&(outMsg2.g_b)), cmac_size, &outMsg2.mac);

	outMsg2.sig_rl_size = 0;

	spCTX.m_state = ClientRAState::MSG1_DONE;

	if (!AddNewClientRAState(clientId, std::move(spCTXPtr)))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return res; //Error return. (Error from SGX)
}

sgx_status_t SGXRAEnclave::ProcessRaMsg3(const std::string& clientId, const uint8_t* inMsg3, uint32_t msg3Len, const std::string& iasReport, const std::string& reportSign, const std::string& reportCert, sgx_ias_report_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign, sgx_report_data_t* outOriRD)
{
	if (!inMsg3 || !msg3Len)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	const sgx_ra_msg3_t& msg3 = *reinterpret_cast<const sgx_ra_msg3_t*>(inMsg3);

	std::shared_ptr<RASPContext> spCTXPtr(FetchSpCtx(clientId));
	if (!spCTXPtr || spCTXPtr->m_state != ClientRAState::MSG1_DONE)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	RASPContext& spCTX = *spCTXPtr;
	std::lock_guard<std::mutex> ctxLock(spCTX.m_mutex);

	sgx_status_t res = SGX_SUCCESS;
	int cmpRes = 0;

	// Compare g_a in message 3 with local g_a.
	if (!consttime_memequal(&(spCTX.m_peerEncrKey), &msg3.g_a, sizeof(sgx_ec256_public_t)))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	//Make sure that msg3_size is bigger than sgx_mac_t.
	uint32_t mac_size = msg3Len - sizeof(sgx_mac_t);
	const uint8_t *p_msg3_cmaced = inMsg3;
	p_msg3_cmaced += sizeof(sgx_mac_t);

	res = verify_cmac128(&(spCTX.m_smk), p_msg3_cmaced, mac_size, (msg3.mac));
	if (res != SGX_SUCCESS)
	{
		return res; //Error return. (Error from SGX)
	}

	//std::memcpy(&spCTX.m_secProp, &msg3.ps_sec_prop, sizeof(sgx_ps_sec_prop_desc_t));

	//const sgx_quote_t* p_quote = reinterpret_cast<const sgx_quote_t *>(msg3->quote);

	sgx_report_data_t report_data = { 0 };

	{
		sgx_sha_state_handle_t sha_handle = nullptr;
		// Verify the report_data in the Quote matches the expected value.
		// The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
		// The second 32 bytes of report_data are set to zero.
		res = sgx_sha256_init(&sha_handle);
		if (res != SGX_SUCCESS)
		{
			return res; //Error return. (Error from SGX)
		}

		res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(spCTX.m_peerEncrKey)), sizeof(sgx_ec256_public_t), sha_handle);
		if (res != SGX_SUCCESS)
		{
			sgx_sha256_close(sha_handle);
			return res;
		}

		res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&spCTX.m_pubKey), sizeof(sgx_ec256_public_t), sha_handle);
		if (res != SGX_SUCCESS)
		{
			sgx_sha256_close(sha_handle);
			return res; //Error return. (Error from SGX)
		}

		res = sgx_sha256_update(reinterpret_cast<const uint8_t*>(&(spCTX.m_vk)), sizeof(sgx_ec_key_128bit_t), sha_handle);
		if (res != SGX_SUCCESS)
		{
			sgx_sha256_close(sha_handle);
			return res; //Error return. (Error from SGX)
		}

		res = sgx_sha256_get_hash(sha_handle, (sgx_sha256_hash_t *)&report_data);
		sgx_sha256_close(sha_handle);
		if (res != SGX_SUCCESS)
		{
			return res; //Error return. (Error from SGX)
		}
	}
	
	if (outOriRD)
	{
		std::memcpy(outOriRD, &report_data, sizeof(sgx_report_data_t));
	}

	bool iasVerifyRes = SGXRAEnclave::VerifyIASReport(*spCTX.m_iasReport, iasReport, reportCert, reportSign, report_data, spCTX.m_reportDataVerifier, spCTX.m_nonce.c_str());
	if (!iasVerifyRes)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	std::memcpy(&outMsg4, spCTX.m_iasReport.get(), sizeof(*spCTX.m_iasReport));

	{
		sgx_ecc_state_handle_t eccState;
		res = sgx_ecc256_open_context(&eccState);
		if (res != SGX_SUCCESS)
		{
			return res; //Error return. (Error from SGX)
		}
		res = sgx_ecdsa_sign(reinterpret_cast<const uint8_t*>(&outMsg4), sizeof(outMsg4), 
			const_cast<sgx_ec256_private_t*>(GeneralEc256Type2Sgx(&(spCTX.m_mySignPrv->m_prvKey))), &outMsg4Sign, eccState);
		if (res != SGX_SUCCESS)
		{
			return res; //Error return. (Error from SGX)
		}
		sgx_ecc256_close_context(eccState);
	}

	if ((outMsg4.m_status == static_cast<uint8_t>(ias_quote_status_t::IAS_QUOTE_OK) || outMsg4.m_status == static_cast<uint8_t>(ias_quote_status_t::IAS_QUOTE_GROUP_OUT_OF_DATE)) &&
		(outMsg4.m_pse_status == static_cast<uint8_t>(ias_pse_status_t::IAS_PSE_NA) || outMsg4.m_pse_status == static_cast<uint8_t>(ias_pse_status_t::IAS_PSE_OK) || outMsg4.m_pse_status == static_cast<uint8_t>(ias_pse_status_t::IAS_PSE_OUT_OF_DATE))
		)
	{
		spCTX.m_state = ClientRAState::ATTESTED;
	}
	else
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGX_SUCCESS;
}

bool SGXRAEnclave::VerifyIASReport(sgx_ias_report_t& outIasReport, const std::string& iasReportStr, const std::string& reportCertStr, const std::string& reportSign, const sgx_report_data_t& oriRD, ReportDataVerifier rdVerifier, const char* nonce)
{
#ifndef SIMULATING_ENCLAVE
	MbedTlsObj::X509Cert trustedIasCert(IAS_REPORT_CERT);
	MbedTlsObj::X509Cert reportCertChain(reportCertStr);
	
	bool certVerRes = trustedIasCert && reportCertChain &&
		reportCertChain.Verify(trustedIasCert, nullptr, nullptr, nullptr, nullptr);

	std::vector<uint8_t> buffer1 = cppcodec::base64_rfc4648::decode<std::vector<uint8_t>, std::string>(reportSign);

	General256Hash hash;
	if (!MbedTlsHelper::CalcHashSha256(iasReportStr, hash))
	{
		return false;
	}

	bool signVerRes = false;
	do
	{
		signVerRes = reportCertChain.GetPublicKey().VerifySignatureSha256(hash, buffer1);
	} while (!signVerRes && reportCertChain.NextCert());

	//COMMON_PRINTF("IAS Report Certs Verify Result:     %s \n", certVerRes ? "Success!" : "Failed!");
	//COMMON_PRINTF("IAS Report Signature Verify Result: %s \n", signVerRes ? "Success!" : "Failed!");

	if (!certVerRes || !signVerRes)
	{
		return false;
	}
#else
	//COMMON_PRINTF("IAS Report Certs Verify Result:     %s \n", "Simulated!");
	//COMMON_PRINTF("IAS Report Signature Verify Result: %s \n", "Simulated!");
#endif // !SIMULATING_ENCLAVE

	sgx_status_t sgxRet;
	std::string idStr;
	std::string nonceInReport;
	sgxRet = ParseIasReport(outIasReport, idStr, nonceInReport, iasReportStr);
	if (sgxRet != SGX_SUCCESS)
	{
		return false;
	}

	bool isQuoteStatusValid = (outIasReport.m_status == static_cast<uint8_t>(ias_quote_status_t::IAS_QUOTE_OK) || outIasReport.m_status == static_cast<uint8_t>(ias_quote_status_t::IAS_QUOTE_GROUP_OUT_OF_DATE));
	bool isPseStatusValid = (outIasReport.m_pse_status == static_cast<uint8_t>(ias_pse_status_t::IAS_PSE_NA) || outIasReport.m_pse_status == static_cast<uint8_t>(ias_pse_status_t::IAS_PSE_OK) || outIasReport.m_pse_status == static_cast<uint8_t>(ias_pse_status_t::IAS_PSE_OUT_OF_DATE));
	//COMMON_PRINTF("IAS Report Is Quote Status Valid:   %s \n", isQuoteStatusValid ? "Yes!" : "No!");
	//COMMON_PRINTF("IAS Report Is PSE Status Valid:     %s \n", isQuoteStatusValid ? "Yes!" : "No!");
	if (!isQuoteStatusValid || !isPseStatusValid)
	{
		return false;
	}

	bool isNonceMatch = true;
	if (nonce)
	{
		isNonceMatch = (std::strlen(nonce) == nonceInReport.size());
		isNonceMatch = isNonceMatch && consttime_memequal(nonceInReport.c_str(), nonce, nonceInReport.size());
		//COMMON_PRINTF("IAS Report Is Nonce Match:          %s \n", isNonceMatch ? "Yes!" : "No!");
		if (!isNonceMatch)
		{
			return false;
		}
	}

	const sgx_report_data_t& reportData = outIasReport.m_quote.report_body.report_data;
	bool isReportDataMatch = rdVerifier(oriRD.d, std::vector<uint8_t>(reportData.d, reportData.d + sizeof(sgx_report_data_t)));
	//COMMON_PRINTF("IAS Report Is Report Data Match:    %s \n", isReportDataMatch ? "Yes!" : "No!");

#ifndef SIMULATING_ENCLAVE
	return certVerRes && signVerRes && isNonceMatch && isReportDataMatch;
#else
	return isNonceMatch && isReportDataMatch;
#endif // !SIMULATING_ENCLAVE
}
