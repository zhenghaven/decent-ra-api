#include "sgx_ra_msg4.h"

#include <map>
#include <string>

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

ias_quote_status_t ParseIASQuoteStatus(const char * statusStr)
{
	return quoteStatusMap[statusStr];
}

ias_pse_status_t ParseIASQuotePSEStatus(const char * statusStr)
{
	return quotePSEStatusMap[statusStr];
}
