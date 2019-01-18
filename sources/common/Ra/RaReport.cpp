#include "RaReport.h"

#include <rapidjson/document.h>

#include "../consttime_memequal.h"
#include "../CommonTool.h"

#include "../Tools/DataCoding.h"
#include "../MbedTls/MbedTlsHelpers.h"
#include "../SGX/IasReport.h"
#include "../SGX/sgx_structs.h"

#include "Crypto.h"

using namespace Decent::Ra;
using namespace Decent::Tools;

namespace
{
	static constexpr uint32_t sk_sec2MicroSec = 1000000;
	static constexpr uint32_t sk_microSec2NanoSec = 1000;
}

bool RaReport::DecentReportDataVerifier(const std::string & pubSignKey, const uint8_t* initData, const uint8_t* expected, const size_t size)
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

bool RaReport::ProcessSelfRaReport(const std::string & platformType, const std::string & pubKeyPem, const std::string & raReport, const std::string & inHashStr, TimeStamp& outTimestamp)
{
	if (platformType == sk_ValueReportTypeSgx)
	{
		sgx_ias_report_t outIasReport;
		bool verifyRes = ProcessSgxSelfRaReport(pubKeyPem, raReport, inHashStr, outIasReport);
		outTimestamp.m_year = outIasReport.m_timestamp.m_year;
		outTimestamp.m_month = outIasReport.m_timestamp.m_month;
		outTimestamp.m_day = outIasReport.m_timestamp.m_day;

		outTimestamp.m_hour = outIasReport.m_timestamp.m_hour;
		outTimestamp.m_min = outIasReport.m_timestamp.m_min;
		outTimestamp.m_sec = static_cast<uint8_t>(outIasReport.m_timestamp.m_sec);
		//TODO: Fix time precision later.
		outTimestamp.m_nanoSec = static_cast<uint32_t>((outIasReport.m_timestamp.m_sec - outTimestamp.m_sec) * sk_sec2MicroSec) * sk_microSec2NanoSec;

		return verifyRes;
	}
	return false;
}

const sgx_ra_config & RaReport::GetSgxDecentRaConfig()
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

bool RaReport::ProcessSgxSelfRaReport(const std::string& pubKeyPem, const std::string & raReport, const std::string & inHashStr, sgx_ias_report_t & outIasReport)
{
	if (raReport.size() == 0)
	{
		return false;
	}

	rapidjson::Document jsonDoc;
	jsonDoc.Parse(raReport.c_str());

	if (!jsonDoc.HasMember(RaReport::sk_LabelRoot))
	{
		return false;
	}
	rapidjson::Value& jsonRoot = jsonDoc[RaReport::sk_LabelRoot];

	std::string iasReportStr = jsonRoot[RaReport::sk_LabelIasReport].GetString();
	std::string iasSign = jsonRoot[RaReport::sk_LabelIasSign].GetString();
	std::string iasCertChain = jsonRoot[RaReport::sk_LabelIasCertChain].GetString();
	std::string oriRDB64 = jsonRoot[RaReport::sk_LabelOriRepData].GetString();

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

	bool reportVerifyRes = Decent::Ias::ParseAndVerifyIasReport(outIasReport, iasReportStr, iasCertChain, iasSign, nullptr, GetSgxDecentRaConfig(), quoteVerifier);
	//COMMON_PRINTF("IAS Report Is Verified:             %s \n", reportVerifyRes ? "Yes!" : "No!");
	//COMMON_PRINTF("IAS Report Is Report Data Match:    %s \n", reportVerifyRes ? "Yes!" : "No!");
	//COMMON_PRINTF("IAS Report Is Hash Match:           %s \n", reportVerifyRes ? "Yes!" : "No!");
	//COMMON_PRINTF("IAS Report Is Quote Status Valid:   %s \n", reportVerifyRes ? "Yes!" : "No!");

	return reportVerifyRes;
}
