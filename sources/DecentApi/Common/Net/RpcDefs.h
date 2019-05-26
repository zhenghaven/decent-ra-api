#pragma once

#include <cstdint>

#include <vector>

#include "../RuntimeException.h"

namespace Decent
{
	namespace Net
	{
		constexpr uint8_t sk_rpcBlockTypeNullTerminated = 0;
		constexpr uint8_t sk_rpcBlockTypePrimitive      = 1;
		constexpr uint8_t sk_rpcBlockTypeVariableLength = 2;
	}
}
