#include "Crypto.h"

#include <sgx_dh.h>

#include "../Common.h"
#include "../RuntimeException.h"
#include "../Tools/DataCoding.h"

#include "RaReport.h"

using namespace Decent::Ra;
using namespace Decent::Tools;

std::string Decent::Ra::GetHashFromAppId(const std::string & platformType, const std::string & appIdStr)
{
	if (platformType == RaReport::sk_ValueReportTypeSgx)
	{
		sgx_dh_session_enclave_identity_t appId;
		DeserializeStruct(appId, appIdStr);

		return SerializeStruct(appId.mr_enclave);
	}
	throw RuntimeException("Platform type of give App ID is not supported.");
}

