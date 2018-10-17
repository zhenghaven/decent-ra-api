#pragma once

#include <string>

namespace StaticConnection
{
	bool Send(void* const connection, const std::string& inMsg);

	bool Send(void* const connection, const void* const data, const size_t dataLen);
	
	int SendRaw(void* const connection, const void* const data, const size_t dataLen);

	bool Receive(void* const connection, std::string& outMsg);
	
	int ReceiveRaw(void* const connection, void* const buf, const size_t bufLen);
}
