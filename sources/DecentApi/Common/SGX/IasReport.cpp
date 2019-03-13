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
#include "../Tools/JsonTools.h"
#include "../Tools/DataCoding.h"
#include "../consttime_memequal.h"
#include "../MbedTls/MbedTlsObjects.h"
#include "../MbedTls/MbedTlsHelpers.h"
#include "IasReportCert.h"
#include "sgx_structs.h"

using namespace Decent;
using namespace Decent::Ias;
using namespace Decent::Tools;

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

	static inline IasRevocReason ParseRevocReason(const int in_num)
	{
		switch (in_num)
		{
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 8:
		case 9:
		case 10:
			return static_cast<IasRevocReason>(in_num);
		default:
			return IasRevocReason::UNSPECIFIED;
		}
	}

	/*
	* There is no much date time libs we can use in sgx SDK. And, since the timestamp format
	* used by IAS API is very straight forward to parse, we can just use our simple functions to parse.
	*/
	static bool ParseTimestampDate(const std::string& dateStr, sgx_timestamp_t& outTime)
	{
		size_t nextPos = 0;
		size_t nextPosAbs = 0;

		int tmpOut[3];
		bool isValid = true;
		for (size_t i = 0; i < 3; ++i)
		{
			try
			{
				tmpOut[i] = std::stoi(dateStr.substr(nextPosAbs), &nextPos);
				isValid = true & isValid;
			}
			catch (const std::exception&)
			{
				isValid = false;
			}
			nextPosAbs += nextPos + 1;
		}
		outTime.m_year = static_cast<uint16_t>(tmpOut[0]); //Year
		outTime.m_month = static_cast<uint8_t>(tmpOut[1]); //Month
		outTime.m_day = static_cast<uint8_t>(tmpOut[2]); //Day

		return isValid;
	}

	static bool ParseTimestampTime(const std::string& timeStr, sgx_timestamp_t& outTime)
	{
		size_t nextPos = 0;
		size_t nextPosAbs = 0;

		int tmpOut[2];
		bool isValid = true;
		for (size_t i = 0; i < 2; ++i)
		{
			try
			{
				tmpOut[i] = std::stoi(timeStr.substr(nextPosAbs), &nextPos);
				isValid = true & isValid;
			}
			catch (const std::exception&)
			{
				isValid = false;
			}
			nextPosAbs += nextPos + 1;
		}
		outTime.m_hour = static_cast<uint8_t>(tmpOut[0]); //Year
		outTime.m_min = static_cast<uint8_t>(tmpOut[1]); //Month

		try
		{
			outTime.m_sec = std::stof(timeStr.substr(nextPosAbs), &nextPos);
			isValid = true & isValid;
		}
		catch (const std::exception&)
		{
			isValid = false;
		}

		return isValid;
	}

	static bool ParseTimestamp(const std::string& timeStr, sgx_timestamp_t& outTime)
	{
		size_t middlePos = timeStr.find('T');
		if (middlePos == std::string::npos || middlePos + 1 == timeStr.size())
		{
			return false;
		}

		bool isValid = ParseTimestampDate(timeStr.substr(0, middlePos), outTime);
		isValid = isValid & ParseTimestampTime(timeStr.substr(middlePos + 1), outTime);

		return isValid;
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

bool Ias::ParseIasReport(sgx_ias_report_t & outReport, std::string& outId, std::string& outNonce, const std::string & inStr)
{
	JsonDoc jsonDoc;
	if (!ParseStr2Json(jsonDoc, inStr))
	{
		return false;
	}

	//ID:
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblId) || !jsonDoc[gsk_repLblId].JSON_IS_STRING())
	{
		return false;
	}
	outId = jsonDoc[gsk_repLblId].JSON_AS_STRING();

	//Timestamp:
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblTimeStp) || !jsonDoc[gsk_repLblTimeStp].JSON_IS_STRING()
		|| !ParseTimestamp(jsonDoc[gsk_repLblTimeStp].JSON_AS_STRING(), outReport.m_timestamp))
	{
		return false;
	}

	//Version:
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblVer) || !jsonDoc[gsk_repLblVer].JSON_IS_NUMBER())
	{
		return false;
	}
	outReport.m_version = static_cast<uint8_t>(jsonDoc[gsk_repLblVer].JSON_AS_INT32());

	//Status:
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblQuoteStat) || !jsonDoc[gsk_repLblQuoteStat].JSON_IS_STRING())
	{
		return false;
	}
	outReport.m_status = static_cast<uint8_t>(GetQuoteStatusMap().at(jsonDoc[gsk_repLblQuoteStat].JSON_AS_STRING()));

	//Revocation Reason:
	outReport.m_revoc_reason = static_cast<uint8_t>(IasRevocReason::UNSPECIFIED);
	if (jsonDoc.JSON_HAS_MEMBER(gsk_repLblRevcRes) && jsonDoc[gsk_repLblRevcRes].JSON_IS_NUMBER())
	{
		outReport.m_revoc_reason = static_cast<uint8_t>(ParseRevocReason(jsonDoc[gsk_repLblRevcRes].JSON_AS_INT32()));
	}

	//PSE status:
	outReport.m_pse_status = static_cast<uint8_t>(IasPseStatus::NA);
	if (jsonDoc.JSON_HAS_MEMBER(gsk_repLblPseStat) && jsonDoc[gsk_repLblPseStat].JSON_IS_STRING())
	{
		outReport.m_pse_status = static_cast<uint8_t>(GetPseStatusMap().at(jsonDoc[gsk_repLblPseStat].JSON_AS_STRING()));
	}

	//PSE Hash:
	if (jsonDoc.JSON_HAS_MEMBER(gsk_repLblPseHash) && jsonDoc[gsk_repLblPseHash].JSON_IS_STRING())
	{
		std::string psehashHex(jsonDoc[gsk_repLblPseHash].JSON_AS_STRING());
		cppcodec::hex_upper::decode(reinterpret_cast<uint8_t*>(&outReport.m_pse_hash), sizeof(outReport.m_pse_hash), psehashHex.c_str(), psehashHex.size());
	}

	//Info Blob:
	if (REP_STAT_EQ_QOT(outReport.m_status, GROUP_REVOKED) || REP_STAT_EQ_QOT(outReport.m_status, GROUP_OUT_OF_DATE) || REP_STAT_EQ_QOT(outReport.m_status, CONFIGURATION_NEEDED) ||
		REP_STAT_EQ_PSE(outReport.m_pse_status, OUT_OF_DATE) || REP_STAT_EQ_PSE(outReport.m_pse_status, REVOKED) || REP_STAT_EQ_PSE(outReport.m_pse_status, RL_VERSION_MISMATCH) )
	{
		if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblInfoBlob) || !jsonDoc[gsk_repLblInfoBlob].JSON_IS_STRING())
		{
			return false;
		}
		std::string infoBlobHex = jsonDoc[gsk_repLblInfoBlob].JSON_AS_STRING();
		uint16_t typeCode = std::stoi(infoBlobHex.substr(0, 4), nullptr, 16);
		uint16_t size = std::stoi(infoBlobHex.substr(4, 4), nullptr, 16);

		infoBlobHex = infoBlobHex.substr(8);

		if (size != sizeof(outReport.m_info_blob))
		{
			return false;
		}
		cppcodec::hex_upper::decode(reinterpret_cast<uint8_t*>(&outReport.m_info_blob), sizeof(outReport.m_info_blob), infoBlobHex.data(), infoBlobHex.size());
	}
	
	//Nonce:
	if (jsonDoc.JSON_HAS_MEMBER(gsk_repLblNonce) && jsonDoc[gsk_repLblNonce].JSON_IS_STRING())
	{
		outNonce = jsonDoc[gsk_repLblNonce].JSON_AS_STRING();
	}

	//epidPseudonym:
	if (jsonDoc.JSON_HAS_MEMBER(gsk_repLblEpidPsy) && jsonDoc[gsk_repLblEpidPsy].JSON_IS_STRING())
	{
		outReport.m_is_epid_pse_valid = 1;
		std::string epidPseHex(jsonDoc[gsk_repLblEpidPsy].JSON_AS_STRING());
		DeserializeStruct(outReport.m_epidPseudonym, epidPseHex);
	}

	//Quote Body:
	if (!jsonDoc.JSON_HAS_MEMBER(gsk_repLblQuoteBody) || !jsonDoc[gsk_repLblQuoteBody].JSON_IS_STRING())
	{
		return false;
	}
	DeserializeStruct(outReport.m_quote, jsonDoc[gsk_repLblQuoteBody].JSON_AS_STRING());

	return true;
}

bool Ias::ParseIasReportAndCheckSignature(sgx_ias_report_t & outIasReport, const std::string & iasReportStr, const std::string & reportCert, const std::string & reportSign, const char * nonce)
{
#ifndef SIMULATING_ENCLAVE
	MbedTlsObj::X509Cert trustedIasCert(Ias::gsk_IasReportCert);
	MbedTlsObj::X509Cert reportCertChain(reportCert);

	//Verify the certificate chain came from the report.
	bool certVerRes = trustedIasCert && reportCertChain &&
		reportCertChain.Verify(trustedIasCert, nullptr, nullptr, nullptr, nullptr);

	if (!certVerRes)
	{
		//LOGI("Certificate chain came from the report is invalid!");
		return false;
	}

	std::vector<uint8_t> signBinBuf = cppcodec::base64_rfc4648::decode<std::vector<uint8_t>, std::string>(reportSign);

	General256Hash hash;
	if (!MbedTlsHelper::CalcHashSha256(iasReportStr, hash))
	{
		return false;
	}

	bool signVerRes = false;
	do
	{
		signVerRes = reportCertChain.GetPublicKey().VerifySignSha256(hash, signBinBuf);
	} while (!signVerRes && reportCertChain.NextCert());

	if (!signVerRes)
	{
		//LOGI("Signature of the report is invalid!");
		return false;
	}

#endif // !SIMULATING_ENCLAVE

	std::string idStr;
	std::string nonceInReport;
	if (!ParseIasReport(outIasReport, idStr, nonceInReport, iasReportStr))
	{
		LOGW("Could not parse the IAS report! Probably the IAS API has been updated recently.");
		return false;
	}

	bool isNonceMatch = true;
	if (nonce)
	{
		isNonceMatch = (std::strlen(nonce) == nonceInReport.size()) && 
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
