#pragma once

#include "../common_app/DecentSgx/DecentApp.h"

class DecentVoteApp : public Decent::DecentSgx::DecentApp
{
public:
	using Decent::DecentSgx::DecentApp::DecentApp;

	virtual ~DecentVoteApp() {}

	bool ProcessVoterMsg(Decent::Net::Connection& connectionPtr);

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Decent::Net::Connection& connection) override;

private:

};
