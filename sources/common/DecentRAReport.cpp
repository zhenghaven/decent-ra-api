
#include "DecentRAReport.h"

#include <rapidjson/document.h>

#include "CommonTool.h"

#include "DataCoding.h"
#include "DecentCrypto.h"
#include "MbedTlsHelpers.h"

#include "SGX/IasReport.h"
#include "SGX/sgx_structs.h"

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

bool Decent::RAReport::ProcessSelfRaReport(const std::string & platformType, const std::string & pubKeyPem, const std::string & raReport, const std::string & inHashStr)
{
	if (platformType == sk_ValueReportTypeSgx)
	{
		sgx_ias_report_t outIasReport;
		return ProcessSgxSelfRaReport(pubKeyPem, raReport, inHashStr, outIasReport);
	}
	return false;
}

const sgx_ra_config & Decent::RAReport::GetSgxDecentRaConfig()
{
	static const sgx_ra_config raCfg
	{
	SGX_QUOTE_LINKABLE_SIGNATURE,
	SGX_DEFAULT_AES_CMAC_KDF_ID,
#ifndef SIMULATING_ENCLAVE
	1,
#else
	0,
#endif 
	1,
	1
	};
	return raCfg;
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

	sgx_measurement_t targetHash;
	DeserializeStruct(targetHash, inHashStr);

	auto quoteVerifier = [&pubKeyPem, &oriReportData, &targetHash](const sgx_ias_report_t & iasReport) -> bool
	{
		return DecentReportDataVerifier(pubKeyPem, oriReportData.d, iasReport.m_quote.report_body.report_data.d, 
			sizeof(sgx_report_data_t) / 2) 
			&&
			consttime_memequal(&iasReport.m_quote.report_body.mr_enclave, &targetHash, sizeof(sgx_measurement_t));
	};

	bool reportVerifyRes = ParseAndVerifyIasReport(outIasReport, iasReportStr, iasCertChain, iasSign, nullptr, GetSgxDecentRaConfig(), quoteVerifier);
	//COMMON_PRINTF("IAS Report Is Verified:             %s \n", reportVerifyRes ? "Yes!" : "No!");
	//COMMON_PRINTF("IAS Report Is Report Data Match:    %s \n", reportVerifyRes ? "Yes!" : "No!");
	//COMMON_PRINTF("IAS Report Is Hash Match:           %s \n", reportVerifyRes ? "Yes!" : "No!");
	//COMMON_PRINTF("IAS Report Is Quote Status Valid:   %s \n", reportVerifyRes ? "Yes!" : "No!");

	return reportVerifyRes;
}
