#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "SGXClientRASession.h"

#include <cstring>
#include <map>
#include <exception>

#include <json/json.h>

#include "../Common.h"
#include "SGXEnclave.h"
#include "SGXMessages/SGXRAMessage.h"
#include "SGXMessages/SGXRAMessage0.h"
#include "SGXMessages/SGXRAMessage1.h"
#include "SGXMessages/SGXRAMessage2.h"
#include "SGXMessages/SGXRAMessage3.h"
#include "SGXMessages/SGXRAMessage4.h"

#include "../MessageException.h"
#include "../Networking/Connection.h"
#include "../../common/DataCoding.h"
#include "../../common/JsonTools.h"

template<class T>
static T*  ParseMessageExpected(const Json::Value& json)
{
	static_assert(std::is_base_of<SGXRAClientMessage, T>::value, "Class type must be a child class of SGXRAClientMessage.");
	
	SGXRAClientMessage::ParseCat(json); //Make sure it's a smart message. Otherwise a ParseException will be thrown.

	if (SGXRAClientMessage::ParseType(json[Messages::sk_LabelRoot]) == SGXRASPErrMsg::sk_ValueType)
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
	DeserializeStruct(res, msg0r.GetRAPubKey());
	return res;
}

static const Json::Value SendAndReceiveHandshakeMsg(Connection& connection, SGXEnclave& enclave)
{
	SGXClientRASession::SendHandshakeMessage(connection, enclave);

	std::string msgBuffer;
	connection.Receive(msgBuffer);

	Json::Value jsonRoot;
	if (!ParseStr2Json(jsonRoot, msgBuffer))
	{
		throw MessageParseException();
	}

	return jsonRoot;
}

void SGXClientRASession::SendHandshakeMessage(Connection& connection, SGXEnclave& enclave)
{
	sgx_ec256_public_t signPubKey;
	enclave.GetRAClientSignPubKey(signPubKey);
	std::string senderID = SerializeStruct(signPubKey);

	SGXRAMessage0Send msg0s(senderID, enclave.GetExGroupID());
	connection.Send(msg0s.ToJsonString());
}

bool SGXClientRASession::SmartMsgEntryPoint(Connection& connection, SGXEnclave & enclave, const Json::Value & msg)
{
	if (SGXRASPMessage::ParseType(msg[Messages::sk_LabelRoot]) == SGXRAMessage0Resp::sk_ValueType)
	{
		SGXRAMessage0Resp msg0r(msg);
		SGXClientRASession raSession(connection, enclave, msg0r);
		bool res = raSession.ProcessClientSideRA();
		return res;
	}
	return false;
}

SGXClientRASession::SGXClientRASession(Connection& connection, SGXEnclave& enclave) :
	SGXClientRASession(connection, enclave, SendAndReceiveHandshakeMsg(connection, enclave))
{
}

SGXClientRASession::SGXClientRASession(Connection& connection, SGXEnclave & enclave, const SGXRAMessage0Resp & msg0r) :
	ClientRASession(connection),
	k_senderId(enclave.GetRAClientSignPubKey()),
	k_remoteSideId(msg0r.GetSenderID()),
	m_hwEnclave(enclave),
	k_remoteSideSignKey(ProcessHandshakeMsgKey(msg0r))
{
}

SGXClientRASession::~SGXClientRASession()
{
}

bool SGXClientRASession::ProcessClientSideRA()
{
	sgx_status_t enclaveRes = SGX_SUCCESS;
	std::string msgBuffer;

	try
	{
		SGXRAClientErrMsg enclaveErrMsg(k_senderId, "Enclave process error!");

		sgx_ra_context_t raContextID = 0;
		sgx_ra_msg1_t msg1Data;

		enclaveRes = m_hwEnclave.ProcessRAMsg0Resp(k_remoteSideId, k_remoteSideSignKey, false, raContextID, msg1Data);
		if (enclaveRes != SGX_SUCCESS)
		{
			m_connection.Send(enclaveErrMsg);
			return false;
		}

		SGXRAMessage1 msg1(k_senderId, msg1Data);

		m_connection.Send(msg1.ToJsonString());
		m_connection.Receive(msgBuffer);
		std::unique_ptr<SGXRAMessage2> msg2(ParseMessageExpected<SGXRAMessage2>(msgBuffer));

		std::vector<uint8_t> msg3Data;
		enclaveRes = m_hwEnclave.ProcessRAMsg2(msg2->GetSenderID(), msg2->GetMsg2Data(), msg3Data, raContextID);
		if (enclaveRes != SGX_SUCCESS)
		{
			m_connection.Send(enclaveErrMsg);
			return false;
		}

		SGXRAMessage3 msg3(k_senderId, msg3Data);

		m_connection.Send(msg3.ToJsonString());
		m_connection.Receive(msgBuffer);
		std::unique_ptr<SGXRAMessage4> msg4(ParseMessageExpected<SGXRAMessage4>(msgBuffer));

		enclaveRes = m_hwEnclave.ProcessRAMsg4(msg4->GetSenderID(), msg4->GetMsg4Data(), msg4->GetMsg4Signature());
		if (enclaveRes != SGX_SUCCESS)
		{
			return false;
		}

		return true;
	}
	catch (const MessageParseException&)
	{
		SGXRAClientErrMsg errMsg(k_senderId, "Received unexpected message! Make sure you are following the protocol.");
		m_connection.Send(errMsg);
		return false;
	}
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
