#pragma once

#include <string>

#include "../common/GeneralKeyTypes.h"
#include "../common/DecentCrypto.h"

namespace Decent
{
	namespace Crypto
	{
		const std::string& GetProgSelfHashBase64();

		const General256Hash& GetGetProgSelfHash256();

		std::shared_ptr<const TlsConfig> GetDecentAppAppServerSideConfig();
		std::shared_ptr<const TlsConfig> GetDecentAppAppClientSideConfig();
		std::shared_ptr<const TlsConfig> GetDecentAppClientServerSideConfig();

		void RefreshDecentAppAppServerSideConfig();
		void RefreshDecentAppAppClientSideConfig();
		void RefreshDecentAppClientServerSideConfig();
	}
}
