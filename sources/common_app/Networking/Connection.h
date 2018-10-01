#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace Json
{
	class Value;
}

class Messages;

class Connection
{
public:
	virtual ~Connection() noexcept {}

	virtual size_t Send(const Messages& msg) = 0;
	virtual size_t Send(const std::string& msg) = 0;
	virtual size_t Send(const Json::Value& msg) = 0;
	virtual size_t Send(const std::vector<uint8_t>& msg) = 0;
	virtual size_t Send(const void* const dataPtr, const size_t size) = 0;

	virtual size_t Receive(std::string& msg) = 0;
	virtual size_t Receive(Json::Value& msg) = 0;
	virtual size_t Receive(std::vector<uint8_t>& msg) = 0;
	virtual size_t Receive(char*& dest) = 0;

	virtual void Terminate() noexcept = 0;
};
