
#include "DecentRAReport.h"

#include <rapidjson/document.h>

#include "CommonTool.h"

#include "DataCoding.h"
#include "DecentCrypto.h"
#include "MbedTlsHelpers.h"

#include "SGX/IasReport.h"
#include "SGX/sgx_structs.h"
#include "SGX/SGXCryptoConversions.h"

bool Decent::RAReport::DecentReportDataVerifier(const std::string & pubSignKey, const uint8_t* initData, const uint8_t* expected, const size_t size)
{
	if (size != GENERAL_256BIT_32BYTE_SIZE ||
		pubSignKey.size() == 0 )
	{
		return false;
	}

	General256Hash hashRes;
	MbedTlsHelper::CalcHashSha256(MbedTlsHelper::hashListMode, 
		{
			{initData, size},
			{pubSignKey.data(), pubSignKey.size()},
		}, hashRes);

	return consttime_memequal(expected, hashRes.data(), hashRes.size()) == 1;
}

bool Decent::RAReport::ProcessSelfRaReport(const std::string & platformType, const std::string & pubKeyPem, const std::string & raReport, const std::string & inHashStr, sgx_ias_report_t & outIasReport)
{
	if (platformType == sk_ValueReportTypeSgx)
	{
		return ProcessSgxSelfRaReport(pubKeyPem, raReport, inHashStr, outIasReport);
	}
	return false;
}

bool Decent::RAReport::ProcessSgxSelfRaReport(const std::string& pubKeyPem, const std::string & raReport, const std::string & inHashStr, sgx_ias_report_t & outIasReport)
{
	if (raReport.size() == 0)
	{
		return false;
	}

	rapidjson::Document jsonDoc;
	jsonDoc.Parse(raReport.c_str());

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

	/*TODO: determine if we need to add nonce in here.*/
	bool reportVerifyRes = ParseAndVerifyIasReport(outIasReport, iasReportStr, iasCertChain, iasSign, nullptr);
	//COMMON_PRINTF("IAS Report Is Verified:             %s \n", reportVerifyRes ? "Yes!" : "No!");
	
	reportVerifyRes = reportVerifyRes && DecentReportDataVerifier(pubKeyPem, oriReportData.d,
		outIasReport.m_quote.report_body.report_data.d, sizeof(sgx_report_data_t) / 2);
	//COMMON_PRINTF("IAS Report Is Report Data Match:    %s \n", reportVerifyRes ? "Yes!" : "No!");

	sgx_measurement_t targetHash;
	DeserializeStruct(targetHash, inHashStr);

	reportVerifyRes = reportVerifyRes && consttime_memequal(&outIasReport.m_quote.report_body.mr_enclave, &targetHash, sizeof(sgx_measurement_t));
	//COMMON_PRINTF("IAS Report Is Hash Match:           %s \n", reportVerifyRes ? "Yes!" : "No!");

	/* TODO: Check Status of PSE: */
	reportVerifyRes = reportVerifyRes && (outIasReport.m_status == static_cast<uint8_t>(ias_quote_status_t::IAS_QUOTE_OK));
	//COMMON_PRINTF("IAS Report Is Quote Status Valid:   %s \n", reportVerifyRes ? "Yes!" : "No!");

	return reportVerifyRes;
}
