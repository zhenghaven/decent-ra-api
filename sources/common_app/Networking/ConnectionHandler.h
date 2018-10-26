#pragma once

#include <string>

class Connection;
namespace Json
{
	class Value;
}

class ConnectionHandler
{
public:
	virtual ~ConnectionHandler() {}

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) = 0;
};
