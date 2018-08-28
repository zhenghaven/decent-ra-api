#include "SGXClientRASession.h"

#include <cstring>
#include <map>
#include <exception>

#include <json/json.h>

#include "../Common.h"
#include "SGXEnclave.h"
#include "SGXRAMessages/SGXRAMessage.h"
#include "SGXRAMessages/SGXRAMessage0.h"
#include "SGXRAMessages/SGXRAMessage1.h"
#include "SGXRAMessages/SGXRAMessage2.h"
#include "SGXRAMessages/SGXRAMessage3.h"
#include "SGXRAMessages/SGXRAMessage4.h"

#include "../MessageException.h"
#include "../Networking/Connection.h"
#include "../../common/DataCoding.h"
#include "../../common/JsonTools.h"
#include "../../common/SGX/sgx_ra_msg4.h"

template<class T>
static T*  ParseMessageExpected(const Json::Value& json)
{
	static_assert(std::is_base_of<SGXRAClientMessage, T>::value, "Class type must be a child class of SGXRAClientMessage.");
	
	SGXRAClientMessage::ParseCat(json); //Make sure it's a smart message. Otherwise a ParseException will be thrown.

	if (SGXRAClientMessage::ParseType(json[Messages::LABEL_ROOT]) == SGXRASPErrMsg::VALUE_TYPE)
	{
		throw ReceivedErrorMessageException();
	}

	return new T(json);
}

template<class T>
static T* ParseMessageExpected(const std::string& jsonStr)
{
	static_assert(std::is_base_of<SGXRAClientMessage, T>::value, "Class type must be a child class of SGXRAClientMessage.");

	Json::Value jsonRoot;
	if (!ParseStr2Json(jsonRoot, jsonStr))
	{
		throw MessageParseException();
	}

	return ParseMessageExpected<T>(jsonRoot);
}

static sgx_ec256_public_t ProcessHandshakeMsgKey(const SGXRAMessage0Resp & msg0r)
{
	sgx_ec256_public_t res;
	DeserializePubKey(msg0r.GetRAPubKey(), res);
	return res;
}

static const Json::Value SendAndReceiveHandshakeMsg(std::unique_ptr<Connection>& connection, SGXEnclave& enclave)
{
	SGXClientRASession::SendHandshakeMessage(connection, enclave);

	std::string msgBuffer;
	connection->Receive(msgBuffer);

	Json::Value jsonRoot;
	if (!ParseStr2Json(jsonRoot, msgBuffer))
	{
		throw MessageParseException();
	}

	return jsonRoot;
}

void SGXClientRASession::SendHandshakeMessage(std::unique_ptr<Connection>& connection, SGXEnclave& enclave)
{
	sgx_ec256_public_t signPubKey;
	enclave.GetRAClientSignPubKey(signPubKey);
	std::string senderID = SerializePubKey(signPubKey);

	SGXRAMessage0Send msg0s(senderID, enclave.GetExGroupID());
	connection->Send(msg0s.ToJsonString());
}

bool SGXClientRASession::SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, SGXEnclave & enclave, const Json::Value & msg)
{
	if (SGXRASPMessage::ParseType(msg[Messages::LABEL_ROOT]) == SGXRAMessage0Resp::VALUE_TYPE)
	{
		SGXRAMessage0Resp msg0r(msg);
		SGXClientRASession raSession(connection, enclave, msg0r);
		bool res = raSession.ProcessClientSideRA();
		raSession.SwapConnection(connection);
		return res;
	}
	return false;
}

SGXClientRASession::SGXClientRASession(std::unique_ptr<Connection>& connection, SGXEnclave& enclave) :
	SGXClientRASession(connection, enclave, SendAndReceiveHandshakeMsg(connection, enclave))
{
}

SGXClientRASession::SGXClientRASession(std::unique_ptr<Connection>& connection, SGXEnclave & enclave, const SGXRAMessage0Resp & msg0r) :
	ClientRASession(connection, enclave),
	m_sgxEnclave(enclave),
	k_remoteSideID(msg0r.GetSenderID()),
	k_remoteSideSignKey(ProcessHandshakeMsgKey(msg0r))
{
}

SGXClientRASession::~SGXClientRASession()
{
}

bool SGXClientRASession::ProcessClientSideRA()
{
	if (!m_connection)
	{
		return false;
	}

	sgx_status_t enclaveRes = SGX_SUCCESS;
	std::string msgBuffer;

	try
	{
		SGXRAClientErrMsg enclaveErrMsg(k_raSenderID, "Enclave process error!");

		sgx_ra_context_t raContextID = 0;
		sgx_ra_msg1_t msg1Data;

		enclaveRes = m_sgxEnclave.ProcessRAMsg0Resp(k_remoteSideID, k_remoteSideSignKey, false, raContextID, msg1Data);
		if (enclaveRes != SGX_SUCCESS)
		{
			m_connection->Send(enclaveErrMsg);
			return false;
		}

		SGXRAMessage1 msg1(k_raSenderID, msg1Data);

		m_connection->Send(msg1.ToJsonString());
		m_connection->Receive(msgBuffer);
		std::unique_ptr<SGXRAMessage2> msg2(ParseMessageExpected<SGXRAMessage2>(msgBuffer));

		std::vector<uint8_t> msg3Data;
		enclaveRes = m_sgxEnclave.ProcessRAMsg2(msg2->GetSenderID(), msg2->GetMsg2Data(), msg3Data, raContextID);
		if (enclaveRes != SGX_SUCCESS)
		{
			m_connection->Send(enclaveErrMsg);
			return false;
		}

		SGXRAMessage3 msg3(k_raSenderID, msg3Data);

		m_connection->Send(msg3.ToJsonString());
		m_connection->Receive(msgBuffer);
		std::unique_ptr<SGXRAMessage4> msg4(ParseMessageExpected<SGXRAMessage4>(msgBuffer));

		enclaveRes = m_sgxEnclave.ProcessRAMsg4(msg4->GetSenderID(), msg4->GetMsg4Data(), msg4->GetMsg4Signature(), raContextID);
		if (enclaveRes != SGX_SUCCESS)
		{
			return false;
		}

		return true;
	}
	catch (const MessageParseException&)
	{
		SGXRAClientErrMsg errMsg(k_raSenderID, "Received unexpected message! Make sure you are following the protocol.");
		m_connection->Send(errMsg);
		return false;
	}
}
