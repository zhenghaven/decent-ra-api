#pragma once

#include <string>

namespace StaticConnection
{
	bool SendPack(void* const connection, const std::string& inMsg);

	bool SendPack(void* const connection, const void* const data, const size_t dataLen);
	
	int SendRaw(void* const connection, const void* const data, const size_t dataLen);

	bool ReceivePack(void* const connection, std::string& outMsg);
	
	int ReceiveRaw(void* const connection, void* const buf, const size_t bufLen);

	bool SendAndReceivePack(void* const connection, const void* const inData, const size_t inDataLen, std::string& outMsg);
}
