#include "IasReport.h"

#include <map>
#include <string>

#include <cppcodec/hex_default_upper.hpp>
#include <cppcodec/base64_rfc4648.hpp>

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif // ENCLAVE_ENVIRONMENT

#include "../Common.h"
#include "../consttime_memequal.h"
#include "../Tools/JsonTools.h"
#include "../Tools/DataCoding.h"
#include "../MbedTls/MbedTlsObjects.h"
#include "../MbedTls/Hasher.h"
#include "IasReportCert.h"
#include "sgx_structs.h"

using namespace Decent;
using namespace Decent::Ias;
using namespace Decent::Tools;

#define THROW_REPORT_PARSE_ERROR(ERR) throw ReportParseError("Failed to parse IAS Report: " ERR);

namespace
{
	static const std::map<std::string, IasQuoteStatus>& GetQuoteStatusMap()
	{//As long as we keep updated with IAS's API, we won't get exception about out of range.
		static const std::map<std::string, IasQuoteStatus> quoteStatusMap =
		{
			std::make_pair("OK",                     IasQuoteStatus::OK),
			std::make_pair("SIGNATURE_INVALID",      IasQuoteStatus::SIGNATURE_INVALID),
			std::make_pair("GROUP_REVOKED",          IasQuoteStatus::GROUP_REVOKED),
			std::make_pair("SIGNATURE_REVOKED",      IasQuoteStatus::SIGNATURE_REVOKED),
			std::make_pair("KEY_REVOKED",            IasQuoteStatus::KEY_REVOKED),
			std::make_pair("SIGRL_VERSION_MISMATCH", IasQuoteStatus::SIGRL_VERSION_MISMATCH),
			std::make_pair("GROUP_OUT_OF_DATE",      IasQuoteStatus::GROUP_OUT_OF_DATE),
			std::make_pair("CONFIGURATION_NEEDED",   IasQuoteStatus::CONFIGURATION_NEEDED),
		};

		return quoteStatusMap;
	}

	static const std::map<std::string, IasPseStatus>& GetPseStatusMap()
	{
		static const std::map<std::string, IasPseStatus> pseStatusMap =
		{
			std::make_pair("OK",                  IasPseStatus::OK),
			std::make_pair("UNKNOWN",             IasPseStatus::UNKNOWN),
			std::make_pair("INVALID",             IasPseStatus::INVALID),
			std::make_pair("OUT_OF_DATE",         IasPseStatus::OUT_OF_DATE),
			std::make_pair("REVOKED",             IasPseStatus::REVOKED),
			std::make_pair("RL_VERSION_MISMATCH", IasPseStatus::RL_VERSION_MISMATCH),
		};

		return pseStatusMap;
	}

	static inline uint8_t ParseRevocReason(const int inNum)
	{
		IasRevocReason readable = static_cast<IasRevocReason>(inNum);
		switch (readable)
		{
		case IasRevocReason::UNSPECIFIED:
		case IasRevocReason::KEY_COMPROMISE:
		case IasRevocReason::CA_COMPROMISED:
		case IasRevocReason::AFFILIATION_CHANGED:
		case IasRevocReason::SUPERCEDED:
		case IasRevocReason::CESSATION_OF_OPERATION:
		case IasRevocReason::CERTIFICATE_HOLD:
		case IasRevocReason::REMOVE_FROM_CRL:
		case IasRevocReason::PRIVILEGE_WITHDRAWN:
		case IasRevocReason::AA_COMPROMISE:
			return static_cast<uint8_t>(inNum);
		default:
			THROW_REPORT_PARSE_ERROR("Failed to parse revocation reason.");
		}
	}

	/*
	* There is no much date time libs we can use in sgx SDK. And, since the timestamp format
	* used by IAS API is very straight forward to parse, we can just use our simple functions to parse.
	*/
	static void ParseTimestampDate(const std::string& dateStr, report_timestamp_t& outTime)
	{
		size_t nextPos = 0;
		size_t nextPosAbs = 0;

		int tmpOut[3];
		for (size_t i = 0; i < 3; ++i)
		{
			try
			{
				tmpOut[i] = std::stoi(dateStr.substr(nextPosAbs), &nextPos);
			}
			catch (const std::exception&)
			{
				THROW_REPORT_PARSE_ERROR("Failed to parse date field in timestamp.");
			}
			nextPosAbs += nextPos + 1;
		}
		outTime.m_year = static_cast<uint16_t>(tmpOut[0]); //Year
		outTime.m_month = static_cast<uint8_t>(tmpOut[1]); //Month
		outTime.m_day = static_cast<uint8_t>(tmpOut[2]); //Day
	}

	static void ParseTimestampTime(const std::string& timeStr, report_timestamp_t& outTime)
	{
		static constexpr uint8_t SEC_PER_MIN = 60;
		static constexpr uint8_t MIN_PER_HOR = 60;
		static constexpr uint16_t NaS_PER_MiS = 1000;

		size_t nextPos = 0;
		size_t nextPosAbs = 0;

		int32_t tmpOut[4];
		for (size_t i = 0; i < 4; ++i)
		{
			try
			{
				tmpOut[i] = static_cast<int32_t>(std::stol(timeStr.substr(nextPosAbs), &nextPos));
			}
			catch (const std::exception&)
			{
				THROW_REPORT_PARSE_ERROR("Failed to parse time field in timestamp.");
			}
			nextPosAbs += nextPos + 1;
		}

		// tmpOut[0] is hour, tmpOut[1] is min, tmpOut[2] is sec, tmpOut[3] is microSec;
		// References shouldn't cost extra computing time in release.
		const int32_t& hour = tmpOut[1];
		const int32_t& min = tmpOut[2];
		const int32_t& sec = tmpOut[3];
		const int32_t& microSec = tmpOut[4];

		outTime.m_sec = ((hour * MIN_PER_HOR) + min) * SEC_PER_MIN;
		outTime.m_nanoSec = microSec * NaS_PER_MiS;
	}

	static void ParseTimestamp(const std::string& timeStr, report_timestamp_t& outTime)
	{
		size_t middlePos = timeStr.find('T');
		if (middlePos == std::string::npos || middlePos + 1 == timeStr.size())
		{
			THROW_REPORT_PARSE_ERROR("Failed to parse timestamp.");
		}

		ParseTimestampDate(timeStr.substr(0, middlePos), outTime);
		ParseTimestampTime(timeStr.substr(middlePos + 1), outTime);
	}

	constexpr char const gsk_repLblId[]        = "id";
	constexpr char const gsk_repLblTimeStp[]   = "timestamp";
	constexpr char const gsk_repLblVer[]       = "version";
	constexpr char const gsk_repLblQuoteStat[] = "isvEnclaveQuoteStatus";
	constexpr char const gsk_repLblRevcRes[]   = "revocationReason";
	constexpr char const gsk_repLblPseStat[]   = "pseManifestStatus";
	constexpr char const gsk_repLblPseHash[]   = "pseManifestHash";
	constexpr char const gsk_repLblInfoBlob[]  = "platformInfoBlob";
	constexpr char const gsk_repLblNonce[]     = "nonce";
	constexpr char const gsk_repLblEpidPsy[]   = "epidPseudonym";
	constexpr char const gsk_repLblQuoteBody[] = "isvEnclaveQuoteBody";
}

#define REP_STAT_EQ_QOT(status, value) (status == static_cast<uint8_t>(IasQuoteStatus::value))
#define REP_STAT_EQ_PSE(status, value) (status == static_cast<uint8_t>(IasPseStatus::value))

static uint8_t ParseQuoteStatus(const std::string& str)
{
	try
	{
		return static_cast<uint8_t>(GetQuoteStatusMap().at(str));
	}
	catch (const std::exception&)
	{
		THROW_REPORT_PARSE_ERROR("Failed to parse report quote status.");
	}
}

static uint8_t ParsePseStatus(const std::string& str)
{
	try
	{
		return static_cast<uint8_t>(GetPseStatusMap().at(str));
	}
	catch (const std::exception&)
	{
		THROW_REPORT_PARSE_ERROR("Failed to parse report PSE status.");
	}
}

void Ias::ParseIasReport(sgx_ias_report_t & outReport, std::string& outId, std::string& outNonce, const std::string & inStr)
{
	JsonDoc jsonDoc;
	ParseStr2Json(jsonDoc, inStr);

	//ID: (Mandatory)
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblId) || !jsonDoc[gsk_repLblId].JSON_IS_STRING())
	{
		THROW_REPORT_PARSE_ERROR("Failed to parse report ID.");
	}
	outId = jsonDoc[gsk_repLblId].JSON_AS_STRING();

	//Timestamp: (Mandatory)
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblTimeStp) || !jsonDoc[gsk_repLblTimeStp].JSON_IS_STRING())
	{
		THROW_REPORT_PARSE_ERROR("Failed to parse report timestamp.");
	}
	ParseTimestamp(jsonDoc[gsk_repLblTimeStp].JSON_AS_STRING(), outReport.m_timestamp);

	//Version: (Mandatory)
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblVer) || !jsonDoc[gsk_repLblVer].JSON_IS_NUMBER())
	{
		THROW_REPORT_PARSE_ERROR("Failed to parse report version.");
	}
	outReport.m_version = static_cast<uint8_t>(jsonDoc[gsk_repLblVer].JSON_AS_INT32());

	//Status: (Mandatory)
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblQuoteStat) || !jsonDoc[gsk_repLblQuoteStat].JSON_IS_STRING())
	{
		THROW_REPORT_PARSE_ERROR("Failed to parse report quote status.");
	}
	outReport.m_status = ParseQuoteStatus(jsonDoc[gsk_repLblQuoteStat].JSON_AS_STRING());

	//Revocation Reason: (Optional, when quoteStatus == GROUP_REVOKED)
	if (REP_STAT_EQ_QOT(outReport.m_status, GROUP_REVOKED))
	{
		if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblRevcRes) || !jsonDoc[gsk_repLblRevcRes].JSON_IS_NUMBER())
		{
			THROW_REPORT_PARSE_ERROR("Failed to parse revocation reason.");
		}
		outReport.m_revoc_reason = ParseRevocReason(jsonDoc[gsk_repLblRevcRes].JSON_AS_INT32());
	}

	//PSE status: (Optional)
	outReport.m_pse_status = static_cast<uint8_t>(IasPseStatus::NA);
	if (jsonDoc.JSON_HAS_MEMBER(gsk_repLblPseStat) && jsonDoc[gsk_repLblPseStat].JSON_IS_STRING())
	{
		outReport.m_pse_status = ParsePseStatus(jsonDoc[gsk_repLblPseStat].JSON_AS_STRING());
	}

	//PSE Hash: (Optional)
	if (jsonDoc.JSON_HAS_MEMBER(gsk_repLblPseHash) && jsonDoc[gsk_repLblPseHash].JSON_IS_STRING())
	{
		std::string psehashHex(jsonDoc[gsk_repLblPseHash].JSON_AS_STRING());
		cppcodec::hex_upper::decode(reinterpret_cast<uint8_t*>(&outReport.m_pse_hash), sizeof(outReport.m_pse_hash), psehashHex.c_str(), psehashHex.size());
	}

	//Info Blob: (Optional)
	if (REP_STAT_EQ_QOT(outReport.m_status, GROUP_REVOKED) || REP_STAT_EQ_QOT(outReport.m_status, GROUP_OUT_OF_DATE) || REP_STAT_EQ_QOT(outReport.m_status, CONFIGURATION_NEEDED) ||
		REP_STAT_EQ_PSE(outReport.m_pse_status, OUT_OF_DATE) || REP_STAT_EQ_PSE(outReport.m_pse_status, REVOKED) || REP_STAT_EQ_PSE(outReport.m_pse_status, RL_VERSION_MISMATCH) )
	{
		if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblInfoBlob) || !jsonDoc[gsk_repLblInfoBlob].JSON_IS_STRING())
		{
			THROW_REPORT_PARSE_ERROR("Failed to parse info blob.");
		}
		std::string infoBlobHex = jsonDoc[gsk_repLblInfoBlob].JSON_AS_STRING();
		uint16_t size = static_cast<uint16_t>(std::stoi(infoBlobHex.substr(4, 4), nullptr, 16));
		if (size != sizeof(outReport.m_info_blob))
		{
			THROW_REPORT_PARSE_ERROR("Failed to parse info blob.");
		}
		//uint16_t typeCode = static_cast<uint16_t>(std::stoi(infoBlobHex.substr(0, 4), nullptr, 16)); //Not in use for now.

		infoBlobHex = infoBlobHex.substr(8);
		cppcodec::hex_upper::decode(reinterpret_cast<uint8_t*>(&outReport.m_info_blob), sizeof(outReport.m_info_blob), infoBlobHex.data(), infoBlobHex.size());
	}
	
	//Nonce: (Optional)
	if (jsonDoc.JSON_HAS_MEMBER(gsk_repLblNonce) && jsonDoc[gsk_repLblNonce].JSON_IS_STRING())
	{
		outNonce = jsonDoc[gsk_repLblNonce].JSON_AS_STRING();
	}

	//epidPseudonym: (Optional)
	if (jsonDoc.JSON_HAS_MEMBER(gsk_repLblEpidPsy) && jsonDoc[gsk_repLblEpidPsy].JSON_IS_STRING())
	{
		outReport.m_is_epid_pse_valid = 1;
		std::string epidPseHex(jsonDoc[gsk_repLblEpidPsy].JSON_AS_STRING());
		DeserializeStruct(outReport.m_epidPseudonym, epidPseHex);
	}

	//Quote Body:
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblQuoteBody) || !jsonDoc[gsk_repLblQuoteBody].JSON_IS_STRING())
	{
		THROW_REPORT_PARSE_ERROR("Failed to parse quote body.");
	}
	DeserializeStruct(outReport.m_quote, jsonDoc[gsk_repLblQuoteBody].JSON_AS_STRING());
}

bool Ias::ParseIasReportAndCheckSignature(sgx_ias_report_t & outIasReport, const std::string & iasReportStr, const std::string & reportCert, const std::string & reportSign, const char * nonce)
{
	using namespace Decent::MbedTlsObj;

	MbedTlsObj::X509Cert trustedIasCert(Ias::gsk_IasReportCert);
	MbedTlsObj::X509Cert reportCertChain(reportCert);

	//Verify the certificate chain came from the report.
	if (!reportCertChain.Verify(trustedIasCert, nullptr, nullptr, nullptr, nullptr))
	{
		//LOGI("Certificate chain came from the report is invalid!");
		return false;
	}

	std::vector<uint8_t> signBinBuf = cppcodec::base64_rfc4648::decode<std::vector<uint8_t>, std::string>(reportSign);

	General256Hash hash;
	Hasher<HashType::SHA256>().Calc(hash, iasReportStr);

	bool signVerRes = false;
	do
	{
		try
		{
			reportCertChain.GetPublicKey().VerifyDerSign(HashType::SHA256, hash, signBinBuf);
			signVerRes = true;
		}
		catch (const std::exception&)
		{}
	} while (!signVerRes && reportCertChain.NextCert());

	if (!signVerRes)
	{
		//LOGI("Signature of the report is invalid!");
		return false;
	}

	std::string idStr;
	std::string nonceInReport;
	ParseIasReport(outIasReport, idStr, nonceInReport, iasReportStr);

	if (nonce)
	{
		bool isNonceMatch = (std::strlen(nonce) == nonceInReport.size()) &&
			consttime_memequal(nonceInReport.c_str(), nonce, nonceInReport.size());
		if (!isNonceMatch)
		{
			//LOGI("Nonce of the report is invalid!");
			return false;
		}
	}

	return true;
}

bool Ias::CheckIasReportStatus(const sgx_ias_report_t & iasReport, const sgx_ra_config & raConfig) noexcept
{
	return (
		REP_STAT_EQ_QOT(iasReport.m_status, OK) ||
		(REP_STAT_EQ_QOT(iasReport.m_status, GROUP_OUT_OF_DATE) && raConfig.allow_ofd_enc) ||
		(REP_STAT_EQ_QOT(iasReport.m_status, CONFIGURATION_NEEDED) && raConfig.allow_cfgn_enc)
		)
		&&
		(
		(REP_STAT_EQ_PSE(iasReport.m_pse_status, NA) && !raConfig.enable_pse) ||
		(
			(
			REP_STAT_EQ_PSE(iasReport.m_pse_status, OK) ||
			(REP_STAT_EQ_PSE(iasReport.m_pse_status, OUT_OF_DATE) && raConfig.allow_ofd_pse)
			)
			&&
			raConfig.enable_pse
		)
		);
}

bool Ias::CheckRaConfigEqual(const sgx_ra_config & a, const sgx_ra_config & b) noexcept
{
	return a.enable_pse == b.enable_pse &&
		a.linkable_sign == b.linkable_sign &&
		a.ckdf_id == b.ckdf_id &&
		a.allow_ofd_enc == b.allow_ofd_enc &&
		a.allow_cfgn_enc == b.allow_cfgn_enc &&
		a.allow_ofd_pse == b.allow_ofd_pse;
}

bool Ias::CheckRaConfigValidaty(const sgx_ra_config & a) noexcept
{
	return (a.linkable_sign == SGX_QUOTE_LINKABLE_SIGNATURE || a.linkable_sign == SGX_QUOTE_UNLINKABLE_SIGNATURE) &&
		(a.enable_pse == 0 || a.enable_pse == 1) &&
		(a.allow_ofd_enc == 0 || a.allow_ofd_enc == 1) &&
		(a.allow_cfgn_enc == 0 || a.allow_cfgn_enc == 1) &&
		(a.allow_ofd_pse == 0 || a.allow_ofd_pse == 1);
}
