#pragma once

#include "../common_app/SGX/SGXDecentAppEnclave.h"

class Connection;

class DecentVoteApp : public SGXDecentAppEnclave
{
public:
	using SGXDecentAppEnclave::SGXDecentAppEnclave;

	virtual ~DecentVoteApp() {}

	bool ProcessVoterMsg(Connection& connectionPtr);

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

private:

};
