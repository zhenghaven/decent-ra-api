#pragma once

#include "../common_app/DecentSgx/DecentApp.h"

class Connection;

class DecentVoteApp : public DecentSgx::DecentApp
{
public:
	using DecentSgx::DecentApp::DecentApp;

	virtual ~DecentVoteApp() {}

	bool ProcessVoterMsg(Connection& connectionPtr);

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

private:

};
