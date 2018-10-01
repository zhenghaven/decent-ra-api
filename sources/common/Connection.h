#pragma once

#include <string>

namespace StaticConnection
{
	bool Send(void* const connection, const std::string& inMsg);

	bool Receive(void* const connection, std::string& outMsg);
}
