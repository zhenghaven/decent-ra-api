#pragma once

#include <string>

class SecureCommLayer
{
public:
	virtual bool DecryptMsg(std::string& outMsg, const char* msg) const = 0;
	virtual bool DecryptMsg(std::string& outMsg, const std::string& msg) const = 0;

	virtual std::string EncryptMsg(const std::string& msg) const = 0;
	virtual bool SendMsg(void* const connectionPtr, const std::string& msg, const char* appAttach) const = 0;
};

