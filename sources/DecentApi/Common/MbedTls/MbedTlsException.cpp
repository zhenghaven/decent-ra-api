#include "MbedTlsException.h"

#include "BigNumber.h"

using namespace Decent::MbedTlsObj;

std::string MbedTlsException::ErrorCodeToHexStr(int error)
{
	const bool isPos = error > 0;
	std::string prefix = isPos ? "0x" : "-0x";
	error = isPos ? error : (-1 * error);

	return prefix + BigNumber::ToHexStr(error, sk_struct, sk_bigEndian);
}
