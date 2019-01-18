#pragma once

#include "../common_app/RaSgx/DecentApp.h"

class DecentVoteApp : public Decent::RaSgx::DecentApp
{
public:
	using Decent::RaSgx::DecentApp::DecentApp;

	virtual ~DecentVoteApp() {}

	bool ProcessVoterMsg(Decent::Net::Connection& connectionPtr);

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Decent::Net::Connection& connection) override;

private:

};
