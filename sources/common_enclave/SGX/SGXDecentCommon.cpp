#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_INTERNAL

#include "SGXDecentCommon.h"

#include <rapidjson/document.h>

#include <sgx_tcrypto.h>

#include <openssl/ec.h>

#include "../../common/OpenSSLTools.h"
#include "../../common/DataCoding.h"
#include "../../common/DecentRAReport.h"

#include "../../common/SGX/sgx_ra_msg4.h"
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

bool DecentEnclave::ProcessIasRaReport(const std::string & inReport, const std::string& inHashStr, sgx_ec256_public_t& outPubKey, std::string* outPubKeyPem, std::string* outIasReport)
{
	rapidjson::Document jsonDoc;
	jsonDoc.Parse(inReport.c_str());

	if (!jsonDoc.HasMember(Decent::RAReport::sk_LabelRoot))
	{
		return false;
	}
	rapidjson::Value& jsonRoot = jsonDoc[Decent::RAReport::sk_LabelRoot];

	if (!jsonRoot.HasMember(Decent::RAReport::sk_LabelType) || 
		!(std::string(jsonRoot[Decent::RAReport::sk_LabelType].GetString()) == Decent::RAReport::sk_ValueReportType))
	{
		return false;
	}

	std::string pubKey = jsonRoot[Decent::RAReport::sk_LabelPubKey].GetString();
	std::string iasReport = jsonRoot[Decent::RAReport::sk_LabelIasReport].GetString();
	std::string iasSign = jsonRoot[Decent::RAReport::sk_LabelIasSign].GetString();
	std::string iasCertChain = jsonRoot[Decent::RAReport::sk_LabelIasCertChain].GetString();
	std::string oriRDB64 = jsonRoot[Decent::RAReport::sk_LabelOriRepData].GetString();
	sgx_report_data_t oriReportData;
	DeserializeStruct(oriReportData, oriRDB64);

	ReportDataVerifier reportDataVerifier = [pubKey](const uint8_t* initData, const std::vector<uint8_t>& inData) -> bool
	{
		return DecentReportDataVerifier(pubKey, initData, inData);
	};

	ias_quote_status_t quoteStatus = ias_quote_status_t::IAS_QUOTE_SIGNATURE_INVALID;
	bool reportVerifyRes = SGXRAEnclave::VerifyIASReport(&quoteStatus, iasReport, iasCertChain, iasSign, inHashStr, oriReportData, reportDataVerifier, nullptr);

	reportVerifyRes = (ECKeyPubPem2SGX(pubKey, outPubKey) && reportVerifyRes);

	if (outPubKeyPem)
	{
		pubKey.swap(*outPubKeyPem);
	}
	if (outIasReport)
	{
		iasReport.swap(*outIasReport);
	}

	return reportVerifyRes;
}



#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
