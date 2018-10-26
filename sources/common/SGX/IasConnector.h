#pragma once

#include <cstdint>

#include <string>

typedef uint8_t sgx_epid_group_id_t[4];
typedef struct _ra_msg3_t sgx_ra_msg3_t;

namespace StaticIasConnector
{
	bool GetRevocationList(const void* const connectorPtr, const sgx_epid_group_id_t& gid, std::string& outRevcList);

	bool GetQuoteReport(const void* const connectorPtr, const sgx_ra_msg3_t& msg3, const size_t msg3Size, const std::string& nonce, const bool pseEnabled, std::string& outReport, std::string& outSign, std::string& outCert);
}
