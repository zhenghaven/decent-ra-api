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

#include "../JsonTools.h"
#include "../CommonTool.h"
#include "../DataCoding.h"
#include "../MbedTlsObjects.h"
#include "../MbedTlsHelpers.h"
#include "IasReportCert.h"
#include "sgx_structs.h"

namespace
{
	std::map<std::string, ias_quote_status_t> quoteStatusMap =
	{
		std::pair<std::string, ias_quote_status_t>("OK", ias_quote_status_t::IAS_QUOTE_OK),
		std::pair<std::string, ias_quote_status_t>("SIGNATURE_INVALID", ias_quote_status_t::IAS_QUOTE_SIGNATURE_INVALID),
		std::pair<std::string, ias_quote_status_t>("GROUP_REVOKED", ias_quote_status_t::IAS_QUOTE_GROUP_REVOKED),
		std::pair<std::string, ias_quote_status_t>("SIGNATURE_REVOKED", ias_quote_status_t::IAS_QUOTE_SIGNATURE_REVOKED),
		std::pair<std::string, ias_quote_status_t>("KEY_REVOKED", ias_quote_status_t::IAS_QUOTE_KEY_REVOKED),
		std::pair<std::string, ias_quote_status_t>("SIGRL_VERSION_MISMATCH", ias_quote_status_t::IAS_QUOTE_SIGRL_VERSION_MISMATCH),
		std::pair<std::string, ias_quote_status_t>("GROUP_OUT_OF_DATE", ias_quote_status_t::IAS_QUOTE_GROUP_OUT_OF_DATE),
	};

	std::map<std::string, ias_pse_status_t> quotePSEStatusMap =
	{
		std::pair<std::string, ias_pse_status_t>("OK", ias_pse_status_t::IAS_PSE_OK),
		std::pair<std::string, ias_pse_status_t>("UNKNOWN", ias_pse_status_t::IAS_PSE_UNKNOWN),
		std::pair<std::string, ias_pse_status_t>("INVALID", ias_pse_status_t::IAS_PSE_INVALID),
		std::pair<std::string, ias_pse_status_t>("OUT_OF_DATE", ias_pse_status_t::IAS_PSE_OUT_OF_DATE),
		std::pair<std::string, ias_pse_status_t>("REVOKED", ias_pse_status_t::IAS_PSE_REVOKED),
		std::pair<std::string, ias_pse_status_t>("RL_VERSION_MISMATCH", ias_pse_status_t::IAS_PSE_RL_VERSION_MISMATCH),
	};
}

static inline ias_quote_status_t ParseIASQuoteStatus(const std::string& statusStr)
{
	return quoteStatusMap[statusStr];
}

static inline ias_pse_status_t ParseIASQuotePSEStatus(const std::string& statusStr)
{
	return quotePSEStatusMap[statusStr];
}

static inline ias_revoc_reason_t parse_revoc_reason(const int in_num)
{
	switch (in_num)
	{
	case 1:
		return ias_revoc_reason_t::IAS_REVOC_REASON_KEY_COMPROMISE;
	case 2:
		return ias_revoc_reason_t::IAS_REVOC_REASON_CA_COMPROMISED;
	case 3:
		return ias_revoc_reason_t::IAS_REVOC_REASON_AFFILIATION_CHANGED;
	case 4:
		return ias_revoc_reason_t::IAS_REVOC_REASON_SUPERCEDED;
	case 5:
		return ias_revoc_reason_t::IAS_REVOC_REASON_CESSATION_OF_OPERATION;
	case 6:
		return ias_revoc_reason_t::IAS_REVOC_REASON_CERTIFICATE_HOLD;
	case 8:
		return ias_revoc_reason_t::IAS_REVOC_REASON_REMOVE_FROM_CRL;
	case 9:
		return ias_revoc_reason_t::IAS_REVOC_REASON_PRIVILEGE_WITHDRAWN;
	case 10:
		return ias_revoc_reason_t::IAS_REVOC_REASON_AA_COMPROMISE;
	default:
		return ias_revoc_reason_t::IAS_REVOC_REASON_UNSPECIFIED;
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

bool ParseIasReport(sgx_ias_report_t & outReport, std::string& outId, std::string& outNonce, const std::string & inStr)
{
	JSON_EDITION::JSON_DOCUMENT_TYPE jsonDoc;
	if (!ParseStr2Json(jsonDoc, inStr))
	{
		return false;
	}

	//ID:
	if (!jsonDoc.JSON_HAS_MEMBER("id") || !jsonDoc["id"].JSON_IS_STRING())
	{
		return false;
	}
	outId = jsonDoc["id"].JSON_AS_STRING();

	//Timestamp:
	if (!jsonDoc.JSON_HAS_MEMBER("timestamp") || !jsonDoc["timestamp"].JSON_IS_STRING()
		|| !ParseTimestamp(jsonDoc["timestamp"].JSON_AS_STRING(), outReport.m_timestamp))
	{
		return false;
	}
	
	//Status:
	if (!jsonDoc.JSON_HAS_MEMBER("isvEnclaveQuoteStatus") || !jsonDoc["isvEnclaveQuoteStatus"].JSON_IS_STRING())
	{
		return false;
	}
	outReport.m_status = static_cast<uint8_t>(ParseIASQuoteStatus(jsonDoc["isvEnclaveQuoteStatus"].JSON_AS_STRING()));

	//Revocation Reason:
	outReport.m_revoc_reason = static_cast<uint8_t>(ias_revoc_reason_t::IAS_REVOC_REASON_UNSPECIFIED);
	if (jsonDoc.JSON_HAS_MEMBER("revocationReason") && jsonDoc["revocationReason"].JSON_IS_NUMBER())
	{
		outReport.m_revoc_reason = static_cast<uint8_t>(parse_revoc_reason(jsonDoc["revocationReason"].JSON_AS_INT32()));
	}
	//PSE status:
	outReport.m_pse_status = ias_pse_status_t::IAS_PSE_NA;
	if (jsonDoc.JSON_HAS_MEMBER("pseManifestStatus") && jsonDoc["pseManifestStatus"].JSON_IS_STRING())
	{
		outReport.m_pse_status = static_cast<uint8_t>(ParseIASQuotePSEStatus(jsonDoc["pseManifestStatus"].JSON_AS_STRING()));
	}

	//PSE Hash:
	if (jsonDoc.JSON_HAS_MEMBER("pseManifestHash") && jsonDoc["pseManifestHash"].JSON_IS_STRING())
	{
		std::string psehashHex(jsonDoc["pseManifestHash"].JSON_AS_STRING());
		cppcodec::hex_upper::decode(reinterpret_cast<uint8_t*>(&outReport.m_pse_hash), sizeof(outReport.m_pse_hash), psehashHex.c_str(), psehashHex.size());
	}

	//Info Blob:
	if (jsonDoc.JSON_HAS_MEMBER("platformInfoBlob") && jsonDoc["platformInfoBlob"].JSON_IS_STRING())
	{
		std::string infoblobHex(jsonDoc["platformInfoBlob"].JSON_AS_STRING());
		cppcodec::hex_upper::decode(reinterpret_cast<uint8_t*>(&outReport.m_info_blob), sizeof(outReport.m_info_blob), infoblobHex.c_str(), infoblobHex.size());
	}

	//Nonce:
	if (jsonDoc.JSON_HAS_MEMBER("nonce") && jsonDoc["nonce"].JSON_IS_STRING())
	{
		outNonce = jsonDoc["nonce"].JSON_AS_STRING();
	}

	//epidPseudonym:
	if (jsonDoc.JSON_HAS_MEMBER("epidPseudonym") && jsonDoc["epidPseudonym"].JSON_IS_STRING())
	{
		std::string epidPseHex(jsonDoc["epidPseudonym"].JSON_AS_STRING());
		DeserializeStruct(outReport.m_epidPseudonym, epidPseHex);
	}

	//Quote Body:
	if (!jsonDoc.JSON_HAS_MEMBER("isvEnclaveQuoteBody") || !jsonDoc["isvEnclaveQuoteBody"].JSON_IS_STRING())
	{
		return false;
	}
	DeserializeStruct(outReport.m_quote, jsonDoc["isvEnclaveQuoteBody"].JSON_AS_STRING());

	return true;
}

bool ParseAndCheckIasReport(sgx_ias_report_t & outIasReport, const std::string & iasReportStr, const std::string & reportCert, const std::string & reportSign, const char * nonce)
{
#ifndef SIMULATING_ENCLAVE
	MbedTlsObj::X509Cert trustedIasCert(IAS_REPORT_CERT);
	MbedTlsObj::X509Cert reportCertChain(reportCert);

	bool certVerRes = trustedIasCert && reportCertChain &&
		reportCertChain.Verify(trustedIasCert, nullptr, nullptr, nullptr, nullptr);

	std::vector<uint8_t> signBinBuf = cppcodec::base64_rfc4648::decode<std::vector<uint8_t>, std::string>(reportSign);

	General256Hash hash;
	if (!MbedTlsHelper::CalcHashSha256(iasReportStr, hash))
	{
		return false;
	}

	bool signVerRes = false;
	do
	{
		signVerRes = reportCertChain.GetPublicKey().VerifySignatureSha256(hash, signBinBuf);
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

	std::string idStr;
	std::string nonceInReport;
	if (!ParseIasReport(outIasReport, idStr, nonceInReport, iasReportStr))
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

	return isNonceMatch;
}

#define REP_STAT_EQ_QOT(status, value) (status == static_cast<uint8_t>(ias_quote_status_t::value))
#define REP_STAT_EQ_PSE(status, value) (status == static_cast<uint8_t>(ias_pse_status_t::value))

bool CheckIasReportStatus(const sgx_ias_report_t & iasReport, const sgx_ra_config & raConfig)
{
	return (
		REP_STAT_EQ_QOT(iasReport.m_status, IAS_QUOTE_OK) ||
		(REP_STAT_EQ_QOT(iasReport.m_status, IAS_QUOTE_GROUP_OUT_OF_DATE) && raConfig.allow_ofd_enc)
		)
		&&
		(
		(REP_STAT_EQ_PSE(iasReport.m_pse_status, IAS_PSE_NA) && !raConfig.enable_pse) ||
		(
			(
			REP_STAT_EQ_PSE(iasReport.m_pse_status, IAS_PSE_OK) ||
			(REP_STAT_EQ_PSE(iasReport.m_pse_status, IAS_PSE_OUT_OF_DATE) && raConfig.allow_ofd_pse)
			)
			&&
			raConfig.enable_pse
		)
		);
}
