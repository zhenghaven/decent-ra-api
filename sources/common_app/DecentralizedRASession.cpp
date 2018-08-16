#include "DecentralizedRASession.h"

#include "Common.h"
#include "ClientRASession.h"
#include "ServiceProviderRASession.h"
#include "DecentralizedEnclave.h"
#include "EnclaveBase.h"
#include "ServiceProviderBase.h"
#include "RAMessageRevRAReq.h"

#include "Networking/Connection.h"

static RAMessages * JsonMessageParser(const std::string& jsonStr)
{
	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(jsonStr.c_str(), jsonStr.c_str() + jsonStr.size(), &jsonRoot, &errStr);

	if (!isValid
		|| !jsonRoot.isMember("MsgSubType")
		|| !jsonRoot["MsgSubType"].isString())
	{
		LOGI("Recv INVALID MESSAGE!");
		return nullptr;
	}

	if (jsonRoot["MsgSubType"].asString() == "ReverseRARequest")
	{
		return new RAMessageRevRAReq(jsonRoot);
	}

	return nullptr;
}

DecentralizedRASession::DecentralizedRASession(std::unique_ptr<Connection>& connection, EnclaveBase& hardwareEnclave, ServiceProviderBase& sp, DecentralizedEnclave& enclave) :
	m_connection(std::move(connection)),
	m_hardwareEnclave(hardwareEnclave),
	m_sp(sp),
	m_hardwareSession(hardwareEnclave.GetRASession()),
	m_spSession(sp.GetRASession()),
	m_decentralizedEnc(enclave)
{
}

DecentralizedRASession::~DecentralizedRASession()
{
}

bool DecentralizedRASession::ProcessClientSideRA()
{
	if (!m_connection)
	{
		return false;
	}

	bool res = true;
	const std::string senderID = m_hardwareSession->GetSenderID();

	m_hardwareSession->SwapConnection(m_connection);
	res = m_hardwareSession->ProcessClientSideRA();
	m_hardwareSession->SwapConnection(m_connection);

	if (!res)
	{
		return res;
	}

	res = SendReverseRARequest(senderID);
	if (!res)
	{
		return res;
	}

	m_spSession->SwapConnection(m_connection);
	res = m_spSession->ProcessServerSideRA();
	m_spSession->SwapConnection(m_connection);

	if (!res)
	{
		return res;
	}

	res = RecvReverseRARequest();

	return res;
}

bool DecentralizedRASession::ProcessServerSideRA()
{
	if (!m_connection)
	{
		return false;
	}

	bool res = true;
	const std::string senderID = m_hardwareSession->GetSenderID();

	m_spSession->SwapConnection(m_connection);
	res = m_spSession->ProcessServerSideRA();
	m_spSession->SwapConnection(m_connection);

	if (!res)
	{
		return res;
	}

	res = RecvReverseRARequest();
	if (!res)
	{
		return res;
	}

	m_hardwareSession->SwapConnection(m_connection);
	res = m_hardwareSession->ProcessClientSideRA();
	m_hardwareSession->SwapConnection(m_connection);

	if (!res)
	{
		return res;
	}

	res = SendReverseRARequest(senderID);

	return res;
}

bool DecentralizedRASession::SendReverseRARequest(const std::string & senderID)
{
	if (!m_connection)
	{
		return false;
	}

	RAMessageRevRAReq msg(senderID);
	m_connection->Send(msg.ToJsonString());

	return true;
}

bool DecentralizedRASession::RecvReverseRARequest()
{
	if (!m_connection)
	{
		return false;
	}

	RAMessages* resp = nullptr;
	std::string msgBuffer;
	m_connection->Receive(msgBuffer);
	resp = JsonMessageParser(msgBuffer);

	RAMessageRevRAReq* revReq = dynamic_cast<RAMessageRevRAReq*>(resp);
	if (!resp || !revReq || !revReq->IsValid())
	{
		delete resp;
		return false;
	}

	delete resp;
	resp = nullptr;
	revReq = nullptr;

	return true;
}

void DecentralizedRASession::AssignConnection(std::unique_ptr<Connection>& inConnection)
{
	m_connection.reset();
	m_connection.swap(inConnection);
}

void DecentralizedRASession::SwapConnection(std::unique_ptr<Connection>& inConnection)
{
	m_connection.swap(inConnection);
}
