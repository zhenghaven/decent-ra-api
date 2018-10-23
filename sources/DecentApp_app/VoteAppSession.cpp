#include "VoteAppSession.h"

#include "VoteAppMessage.h"
#include "DecentVoteApp.h"

#include "../common_app/Logger/Logger.h"
#include "../common_app/Logger/LoggerManager.h"
#include "../common_app/Networking/Connection.h"

bool VoteAppServerSession::SmartMsgEntryPoint(Connection & connection, DecentVoteApp & hwEnclave, const Json::Value & jsonMsg)
{
	const std::string inType = VoteAppMessage::ParseType(jsonMsg[Messages::sk_LabelRoot]);
	if (inType == VoteAppHandshake::sk_ValueType)
	{
		VoteAppHandshake hsMsg(jsonMsg);
		std::unique_ptr<DecentLogger> logger(std::make_unique<DecentLogger>(hsMsg.GetSenderID()));
		logger->AddMessage('I', "Received Vote Request.");
		VoteAppServerSession raSession(connection, hwEnclave, hsMsg);
		bool res = raSession.ProcessServerSide(logger.get());
		logger->AddMessage('I', "Completed Vote Request.");
		DecentLoggerManager::GetInstance().AddLogger(logger);
		return res;
	}

	return false;
}

VoteAppServerSession::VoteAppServerSession(Connection & connection, DecentVoteApp & hwEnclave, const VoteAppHandshake & hsMsg) :
	CommSession(connection),
	k_senderId(""),
	k_remoteSideId(hsMsg.GetSenderID()),
	m_enclave(hwEnclave)
{
	connection.SendPack(VoteAppHandshakeAck(k_senderId, hwEnclave.GetDecentRAReport()));
}

bool VoteAppServerSession::ProcessServerSide(DecentLogger * logger)
{
	bool res = true;

	res = m_enclave.ProcessVoterMsg(m_connection);
	if (res && logger)
	{
		logger->AddMessage('I', "Vote Processed Successfully!");
	}
	else if (logger)
	{
		logger->AddMessage('I', "Vote Processed Failed!");
	}
	return false;
}
