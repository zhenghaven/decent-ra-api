#pragma once

#include <string>

class SecureCommLayer
{
public:
	virtual ~SecureCommLayer() {}

	virtual bool DecryptMsg(std::string& outMsg, const char* msg) = 0;
	virtual bool DecryptMsg(std::string& outMsg, const std::string& msg) = 0;

	virtual bool EncryptMsg(std::string& outMsg, const std::string& inMsg) = 0;

	virtual bool ReceiveMsg(void* const connectionPtr, std::string& outMsg) = 0;
	virtual bool SendMsg(void* const connectionPtr, const std::string& inMsg) = 0;
};

