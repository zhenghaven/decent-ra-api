#include "DecentralizedRASession.h"

#include <json/json.h>

#include "Common.h"
#include "ClientRASession.h"
#include "ServiceProviderRASession.h"
#include "DecentralizedEnclave.h"
#include "EnclaveBase.h"
#include "ServiceProviderBase.h"
#include "DecentralizedMessage.h"
#include "MessageException.h"

#include "Networking/Connection.h"

template<class T>
static T*  ParseMessageExpected(const Json::Value& json)
{
	static_assert(std::is_base_of<DecentralizedMessage, T>::value, "Class type must be a child class of DecentralizedMessage.");
	try
	{
		std::string cat = DecentralizedMessage::ParseCat(json);
		if (cat != DecentralizedMessage::VALUE_CAT)
		{
			return nullptr;
		}

		std::string type = DecentralizedMessage::ParseType(json[Messages::LABEL_ROOT]);

		if (type == DecentralizedErrMsg::VALUE_TYPE)
		{
			throw ReceivedErrorMessageException();
		}

		if (type == T::VALUE_TYPE)
		{
			T* msgPtr = new T(json);
			return msgPtr;
		}
		else
		{
			return nullptr;
		}
	}
	catch (const MessageParseException& e)
	{
		LOGI("Caught Exception: %s\n", e.what());
		return nullptr;
	}
}

template<class T>
static T* ParseMessageExpected(const std::string& jsonStr)
{
	static_assert(std::is_base_of<DecentralizedMessage, T>::value, "Class type must be a child class of DecentralizedMessage.");

	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(jsonStr.c_str(), jsonStr.c_str() + jsonStr.size(), &jsonRoot, &errStr);

	return ParseMessageExpected<T>(jsonRoot);
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

	DecentralizedReverseReq msg(senderID);
	m_connection->Send(msg.ToJsonString());

	return true;
}

bool DecentralizedRASession::RecvReverseRARequest()
{
	if (!m_connection)
	{
		return false;
	}

	std::string msgBuffer;
	m_connection->Receive(msgBuffer);

	auto reqMsg = ParseMessageExpected<DecentralizedReverseReq>(msgBuffer);
	delete reqMsg;

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
