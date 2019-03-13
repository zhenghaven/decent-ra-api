#pragma once

#include <cstdint>

#include <string>
#include <vector>

namespace Decent
{
	namespace Tools
	{
		const std::string& GetSelfHashBase64();

		const std::vector<uint8_t>& GetSelfHash();
	}
}
