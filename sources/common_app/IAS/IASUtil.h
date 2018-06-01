#pragma once

#include <string>

#include <sgx_quote.h>

bool GetRevocationList(const sgx_epid_group_id_t& gid, std::string& outRevcList);
