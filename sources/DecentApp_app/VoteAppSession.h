#pragma once

#include <string>
#include <memory>
#include "../common_app/Net/CommSession.h"

class DecentVoteApp;
class VoteAppHandshake;

namespace Decent
{
	namespace Logger
	{
		class DecentLogger;
	}
}

namespace Json
{
	class Value;
}

class VoteAppServerSession : public Decent::Net::CommSession
{
public:
	static bool SmartMsgEntryPoint(Decent::Net::Connection& connection, DecentVoteApp& hwEnclave, const Json::Value& jsonMsg);

public:
	VoteAppServerSession() = delete;
	VoteAppServerSession(Decent::Net::Connection& connection, DecentVoteApp& hwEnclave, const VoteAppHandshake& hsMsg);

	virtual ~VoteAppServerSession() {}

	virtual bool ProcessServerSide(Decent::Logger::DecentLogger* logger = nullptr);

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

private:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	DecentVoteApp& m_enclave;
};
