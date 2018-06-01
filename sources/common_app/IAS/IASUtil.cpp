#include "IASUtil.h"

#include <vector>
#include <algorithm>
#include <sstream>
#include <iomanip>
//#include <cstdio>

namespace
{
	const std::string IAS_URL_BASE = "https://test-as.sgx.trustedservices.intel.com:443";
	const std::string IAS_URL_SIGRL = IAS_URL_BASE + "/attestation/sgx/v2/sigrl/";
	const std::string IAS_URL_REPORT = IAS_URL_BASE + "/attestation/sgx/v2/report";
}

static std::string toHex(const int v)
{
	std::stringstream stream;
	stream << std::hex << v;
	return stream.str();
}

static std::string GetGIDBigEndianStr(const sgx_epid_group_id_t& gid)
{
	std::vector<uint8_t> gidcpy(sizeof(sgx_epid_group_id_t), 0);
	std::memcpy(&gidcpy[0], &gid, gidcpy.size());
	std::reverse(gidcpy.begin(), gidcpy.end());

	std::string res = "";
	for (int i = 0; i < gidcpy.size(); ++i)
	{
		res += toHex(static_cast<int>(gidcpy[i]));
	}

	return res;
}

bool GetRevocationList(const sgx_epid_group_id_t& gid, std::string & outRevcList)
{
	bool res = true;
	const std::string iasURL = IAS_URL_SIGRL + GetGIDBigEndianStr(gid);
	outRevcList = "";

	return res;
}
