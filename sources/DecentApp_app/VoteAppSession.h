#pragma once

#include <string>
#include <memory>
#include "../common_app/CommSession.h"

class DecentVoteApp;
class VoteAppHandshake;
class DecentLogger;

namespace Json
{
	class Value;
}

class VoteAppServerSession : public CommSession
{
public:
	static bool SmartMsgEntryPoint(Connection& connection, DecentVoteApp& hwEnclave, const Json::Value& jsonMsg);

public:
	VoteAppServerSession() = delete;
	VoteAppServerSession(Connection& connection, DecentVoteApp& hwEnclave, const VoteAppHandshake& hsMsg);

	virtual ~VoteAppServerSession() {}

	virtual bool ProcessServerSide(DecentLogger* logger = nullptr);

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

private:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	DecentVoteApp& m_enclave;
};
