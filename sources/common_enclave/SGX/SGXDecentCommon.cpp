#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_INTERNAL

#include "SGXDecentCommon.h"

#include <rapidjson/document.h>

#include <sgx_tcrypto.h>

#include <openssl/ec.h>

#include "../Common.h"

#include "../../common/OpenSSLTools.h"
#include "../../common/DataCoding.h"
#include "../../common/DecentRAReport.h"

#include "../../common/SGX/ias_report.h"
#include "../../common/SGX/IasReport.h"
#include "../../common/SGX/SGXRAServiceProvider.h"
#include "../../common/SGX/SGXOpenSSLConversions.h"

bool DecentEnclave::DecentReportDataVerifier(const std::string& pubSignKey, const uint8_t* initData, const std::vector<uint8_t>& inData)
{
	if (pubSignKey.size() == 0)
	{
		return false;
	}

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
	enclaveRet = sgx_sha256_update(reinterpret_cast<const uint8_t*>(pubSignKey.data()), static_cast<uint32_t>(pubSignKey.size()), shaState);
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

	return std::memcmp(tmpHash, inData.data(), sizeof(sgx_sha256_hash_t)) == 0;
}

bool DecentEnclave::ProcessIasRaReport(const DecentServerX509 & inX509, const std::string& inHashStr, sgx_ias_report_t& outIasReport)
{
	if (!inX509 
		|| inX509.GetPlatformType() != Decent::RAReport::sk_ValueReportType
		|| !inX509.VerifySignature())
	{
		return false;
	}

	rapidjson::Document jsonDoc;
	jsonDoc.Parse(inX509.GetSelfRaReport().c_str());

	if (!jsonDoc.HasMember(Decent::RAReport::sk_LabelRoot))
	{
		return false;
	}
	rapidjson::Value& jsonRoot = jsonDoc[Decent::RAReport::sk_LabelRoot];

	std::string iasReportStr = jsonRoot[Decent::RAReport::sk_LabelIasReport].GetString();
	std::string iasSign = jsonRoot[Decent::RAReport::sk_LabelIasSign].GetString();
	std::string iasCertChain = jsonRoot[Decent::RAReport::sk_LabelIasCertChain].GetString();
	std::string oriRDB64 = jsonRoot[Decent::RAReport::sk_LabelOriRepData].GetString();
	sgx_report_data_t oriReportData;
	DeserializeStruct(oriReportData, oriRDB64);

	std::string pubKeyPem = inX509.GetPublicKey().ToPemString();
	ReportDataVerifier reportDataVerifier = [pubKeyPem](const uint8_t* initData, const std::vector<uint8_t>& inData) -> bool
	{
		return DecentReportDataVerifier(pubKeyPem, initData, inData);
	};
	/*TODO: determine if we need to add nonce in here.*/
	bool reportVerifyRes = SGXRAEnclave::VerifyIASReport(outIasReport, iasReportStr, iasCertChain, iasSign, oriReportData, reportDataVerifier, nullptr);

	sgx_measurement_t targetHash;
	DeserializeStruct(targetHash, inHashStr);

	reportVerifyRes = reportVerifyRes && consttime_memequal(&outIasReport.m_quote.report_body.mr_enclave, &targetHash, sizeof(sgx_measurement_t));
	//COMMON_PRINTF("IAS Report Is Hash Match:           %s \n", reportVerifyRes ? "Yes!" : "No!");

	reportVerifyRes = reportVerifyRes && (outIasReport.m_status == static_cast<uint8_t>(ias_quote_status_t::IAS_QUOTE_OK));
	//COMMON_PRINTF("IAS Report Is Quote Status Valid:   %s \n", reportVerifyRes ? "Yes!" : "No!");

	return reportVerifyRes;
}



#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
