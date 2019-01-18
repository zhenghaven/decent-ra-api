#include "DecentVoteApp.h"

#include <cstdio>

#include <Enclave_u.h>

#include "VoteAppMessage.h"
#include "VoteAppSession.h"

bool DecentVoteApp::ProcessVoterMsg(Decent::Net::Connection & connectionPtr)
{
	int retVal = 0;
	sgx_status_t enclaveRet = ecall_vote_app_proc_voter_msg(GetEnclaveId(), &retVal, &connectionPtr);
	return enclaveRet == SGX_SUCCESS && retVal;
}

bool DecentVoteApp::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Decent::Net::Connection & connection)
{
	if (category == VoteAppMessage::sk_ValueCat)
	{
		return VoteAppServerSession::SmartMsgEntryPoint(connection, *this, jsonMsg);
	}
	else
	{
		return Decent::DecentSgx::DecentApp::ProcessSmartMessage(category, jsonMsg, connection);
	}
}
