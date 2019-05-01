#include "DataSealer.h"

#include "../../Common/MbedTls/Kdf.h"

using namespace Decent::Tools;
using namespace Decent::MbedTlsObj;

void DataSealer::detail::DeriveSealKey(KeyPolicy keyPolicy, const std::string& label, void* outKey, const size_t expectedKeySize, const std::vector<uint8_t>& salt, const std::vector<uint8_t>& meta)
{
	std::vector<uint8_t> rootSealKey = detail::PlatformDeriveSealKey(keyPolicy, meta);

	HKDF<HashType::SHA256>(rootSealKey, label, salt, outKey, expectedKeySize);
}
