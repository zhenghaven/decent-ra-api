#include "SGXRAServiceProvider.h"

#include <cstdlib>
#include <string>
#include <map>
#include <memory>
#include <atomic>
#include <mutex>

#include <sgx_quote.h>
#include <sgx_key_exchange.h>

#include <mbedtls/md.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "SGXCryptoConversions.h"

#include "../CommonTool.h"
#include "../DataCoding.h"
#include "../MbedTlsObjects.h"
#include "../MbedTlsHelpers.h"
#include "../AESGCMCommLayer.h"
#include "../GeneralKeyTypes.h"
#include "../CryptoKeyContainer.h"

#include "../SGX/ias_report_cert.h"
#include "../SGX/sgx_constants.h"
#include "../SGX/ias_report.h"
#include "../SGX/IasReport.h"

enum class ClientRAState
{
	MSG0_DONE,
	MSG1_DONE,
	ATTESTED, //MSG3_DONE,
};

static std::string ConstructNonce(size_t size)
{
	size_t dataSize = (size / 4) * 3;
	std::vector<uint8_t> randData(dataSize);

	void* drbgCtx;
	MbedTlsHelper::DrbgInit(drbgCtx);
	int mbedRet = MbedTlsHelper::DrbgRandom(drbgCtx, randData.data(), randData.size());
	MbedTlsHelper::DrbgFree(drbgCtx);
	if (mbedRet != 0)
	{
		return std::string();
	}

	return cppcodec::base64_rfc4648::encode(randData);
}

struct RASPContext
{
	std::shared_ptr<const general_secp256r1_public_t> m_mySignPub;
	std::shared_ptr<const MbedTlsObj::ECKeyPair> m_mySignPrv;

	MbedTlsObj::ECKeyPair m_encrKeyPair;

	//Do not move the following members:
	general_secp256r1_public_t m_pubKey;
	general_secp256r1_public_t m_peerEncrKey;
	//End Do Not Move.

	std::string m_nonce;
	ReportDataVerifier m_reportDataVerifier;
	//sgx_ec256_dh_shared_t m_sharedKey;
	General128BitKey m_smk;
	std::unique_ptr<General128BitKey> m_mk;
	std::unique_ptr<General128BitKey> m_sk;
	General128BitKey m_vk = { 0 };
	//sgx_ps_sec_prop_desc_t m_secProp;
	ClientRAState m_state;
	std::mutex m_mutex;
	std::unique_ptr<sgx_ias_report_t> m_iasReport;
	bool m_isValid;

	RASPContext(const CryptoKeyContainer& keyContainer) :
		m_mySignPub(keyContainer.GetSignPubKey()),
		m_mySignPrv(keyContainer.GetSignKeyPair()),
		m_encrKeyPair(MbedTlsObj::ECKeyPair::generatePair),
		m_nonce(ConstructNonce(IAS_REQUEST_NONCE_SIZE)),
		//m_sharedKey({ {0} }),
		m_mk(new General128BitKey),
		m_sk(new General128BitKey),
		//m_secProp({ {0} }),
		m_state(ClientRAState::MSG0_DONE),
		m_iasReport(new sgx_ias_report_t),
		m_isValid(m_encrKeyPair && m_encrKeyPair.ToGeneralPublicKey(m_pubKey) && m_nonce.size() == IAS_REQUEST_NONCE_SIZE)
	{
		m_reportDataVerifier = [](const uint8_t* initData, const std::vector<uint8_t>& inData) -> bool
		{
			return consttime_memequal(initData, inData.data(), inData.size()) == 1;
		};
	}

	operator bool() const
	{
		return m_isValid;
	}

	bool SetEncrPubKey(const general_secp256r1_public_t& inEncrPubKey)
	{
		std::memcpy(&m_peerEncrKey, &inEncrPubKey, sizeof(general_secp256r1_public_t));

		MbedTlsObj::ECKeyPublic peerEncrKey(inEncrPubKey);
		if (!peerEncrKey)
		{
			return false;
		}
		General256BitKey sharedKey;
		if (!m_encrKeyPair.GenerateSharedKey(sharedKey, peerEncrKey))
		{
			return false;
		}

		if (!MbedTlsHelper::CkdfAes128(sharedKey, "SMK", m_smk) ||
			!MbedTlsHelper::CkdfAes128(sharedKey, "MK", *m_mk) ||
			!MbedTlsHelper::CkdfAes128(sharedKey, "SK", *m_sk) ||
			!MbedTlsHelper::CkdfAes128(sharedKey, "VK", m_vk))
		{
			return false;
		}
		return true;
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

bool SGXRAEnclave::ReleaseClientKeys(const std::string & clientID, std::unique_ptr<sgx_ias_report_t>& outIasReport, std::unique_ptr<General128BitKey>& outSK, std::unique_ptr<General128BitKey>& outMK)
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
	std::shared_ptr<RASPContext> spCTXPtr(new RASPContext(CryptoKeyContainer::GetInstance()));
	if (!spCTXPtr || !*spCTXPtr)
	{
		return SGX_ERROR_UNEXPECTED;
	}
	RASPContext& spCTX = *spCTXPtr;

	sgx_status_t res = SGX_SUCCESS;

	if (!spCTX.SetEncrPubKey(SgxEc256Type2General(inMsg1.g_a)))
	{
		return SGX_ERROR_UNEXPECTED;
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

	General256Hash hashToBeSigned;
	MbedTlsHelper::CalcHashSha256(&spCTX.m_pubKey, 2 * sizeof(sgx_ec256_public_t), hashToBeSigned);

	if(!spCTX.m_mySignPrv->EcdsaSign(SgxEc256Type2General(outMsg2.sign_gb_ga), hashToBeSigned, 
		mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256)))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	outMsg2.sig_rl_size = 0;

	uint32_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
	General128Tag cmac;
	if (!MbedTlsHelper::CalcCmacAes128(spCTX.m_smk, reinterpret_cast<uint8_t*>(&(outMsg2.g_b)), cmac_size, cmac))
	{
		return SGX_ERROR_UNEXPECTED;
	}
	std::copy(cmac.begin(), cmac.end(), std::begin(outMsg2.mac));

	spCTX.m_state = ClientRAState::MSG1_DONE;

	if (!AddNewClientRAState(clientId, std::move(spCTXPtr)))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	return SGX_SUCCESS; //Error return. (Error from SGX)
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

	General128Tag msg3Mac;
	std::copy(std::begin(msg3.mac), std::end(msg3.mac), msg3Mac.begin());
	if (!MbedTlsHelper::VerifyCmacAes128(spCTX.m_smk, p_msg3_cmaced, mac_size, msg3Mac))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	//std::memcpy(&spCTX.m_secProp, &msg3.ps_sec_prop, sizeof(sgx_ps_sec_prop_desc_t));

	//const sgx_quote_t* p_quote = reinterpret_cast<const sgx_quote_t *>(msg3->quote);

	sgx_report_data_t report_data = { 0 };

	{
		sgx_sha_state_handle_t sha_handle = nullptr;
		// Verify the report_data in the Quote matches the expected value.
		// The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
		// The second 32 bytes of report_data are set to zero.
		General256Hash reportDataHash;
		MbedTlsHelper::CalcHashSha256(MbedTlsHelper::hashListMode, {
			{&(spCTX.m_peerEncrKey), sizeof(sgx_ec256_public_t)},
			{&(spCTX.m_pubKey), sizeof(sgx_ec256_public_t)},
			{&(spCTX.m_vk), sizeof(sgx_ec_key_128bit_t)},
			},
			reportDataHash);
		
		std::copy(reportDataHash.begin(), reportDataHash.end(), report_data.d);
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

	General256Hash hashToBeSigned;
	MbedTlsHelper::CalcHashSha256(&outMsg4, sizeof(outMsg4), hashToBeSigned);

	if(!spCTX.m_mySignPrv->EcdsaSign(SgxEc256Type2General(outMsg4Sign), hashToBeSigned, 
		mbedtls_md_info_from_type(mbedtls_md_type_t::MBEDTLS_MD_SHA256)))
	{
		return SGX_ERROR_UNEXPECTED;
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
