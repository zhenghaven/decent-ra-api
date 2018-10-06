#include "IasReport.h"
#include "ias_report.h"

#include <map>
#include <string>

#include <cppcodec/hex_default_upper.hpp>

#ifdef ENCLAVE_ENVIRONMENT
#include <rapidjson/document.h>
#else
#include <json/json.h>
#endif // ENCLAVE_ENVIRONMENT

#include "../JsonTools.h"
#include "../DataCoding.h"

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

sgx_status_t parse_ias_report(sgx_ias_report_t * out_report, const char * in_str)
{
	if (!out_report || !in_str)
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	std::string nonce;
	std::string id;
	return ParseIasReport(*out_report, id, nonce, in_str);
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

sgx_status_t ParseIasReport(sgx_ias_report_t & outReport, std::string& outId, std::string& outNonce, const std::string & inStr)
{
	JSON_EDITION::JSON_DOCUMENT_TYPE jsonDoc;
	if (!ParseStr2Json(jsonDoc, inStr))
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}

	//ID:
	if (!jsonDoc.JSON_HAS_MEMBER("id") || !jsonDoc["id"].JSON_IS_STRING())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	outId = jsonDoc["id"].JSON_AS_STRING();

	//Timestamp:
	if (!jsonDoc.JSON_HAS_MEMBER("timestamp") || !jsonDoc["timestamp"].JSON_IS_STRING())
	{
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	//Status:
	if (!jsonDoc.JSON_HAS_MEMBER("isvEnclaveQuoteStatus") || !jsonDoc["isvEnclaveQuoteStatus"].JSON_IS_STRING())
	{
		return SGX_ERROR_INVALID_PARAMETER;
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
		outReport.m_revoc_reason = static_cast<uint8_t>(ParseIASQuotePSEStatus(jsonDoc["pseManifestStatus"].JSON_AS_STRING()));
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
		return SGX_ERROR_INVALID_PARAMETER;
	}
	DeserializeStruct(outReport.m_quote, jsonDoc["isvEnclaveQuoteBody"].JSON_AS_STRING());

	return sgx_status_t();
}
