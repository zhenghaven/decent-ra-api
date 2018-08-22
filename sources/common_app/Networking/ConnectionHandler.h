#pragma once

#include <string>
#include <memory>

class Connection;
namespace Json
{
	class Value;
}

class ConnectionHandler
{
public:
	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, std::unique_ptr<Connection>& connection) = 0;
};
