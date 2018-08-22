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
#include "../../common/SGX/sgx_ra_msg4.h"

template<class T>
static T*  ParseMessageExpected(const Json::Value& json)
{
	static_assert(std::is_base_of<SGXRAClientMessage, T>::value, "Class type must be a child class of SGXRAClientMessage.");
	try
	{
		std::string cat = SGXRAClientMessage::ParseCat(json);
		if (cat != SGXRAClientMessage::VALUE_CAT)
		{
			return nullptr;
		}

		std::string type = SGXRAClientMessage::ParseType(json[Messages::LABEL_ROOT]);

		if (type == SGXRASPErrMsg::VALUE_TYPE)
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
	catch (MessageParseException& e)
	{
		LOGI("Caught Exception: %s\n", e.what());
		return nullptr;
	}
}

template<class T>
static T* ParseMessageExpected(const std::string& jsonStr)
{
	static_assert(std::is_base_of<SGXRAClientMessage, T>::value, "Class type must be a child class of SGXRAClientMessage.");

	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(jsonStr.c_str(), jsonStr.c_str() + jsonStr.size(), &jsonRoot, &errStr);

	return ParseMessageExpected<T>(jsonRoot);
}

static SGXRAMessage0Resp ParseHandshakeMsg(const Json::Value& msg)
{
	SGXRAMessage0Resp* msg0r = ParseMessageExpected<SGXRAMessage0Resp>(msg);
	if (!msg0r)
	{
		throw MessageInvalidException();
	}
	SGXRAMessage0Resp res(*msg0r);
	delete msg0r;
	return res;
}

static sgx_ec256_public_t ProcessHandshakeMsgKey(const SGXRAMessage0Resp & msg0r)
{
	sgx_ec256_public_t res;
	DeserializePubKey(msg0r.GetRAPubKey(), res);
	return res;
}

static const Json::Value SendAndReceiveHandshakeMsg(std::unique_ptr<Connection>& connection, SGXEnclave& enclave)
{
	sgx_ec256_public_t signPubKey;
	enclave.GetRAClientSignPubKey(signPubKey);
	std::string senderID = SerializePubKey(signPubKey);

	SGXRAMessage0Send msg0s(senderID, enclave.GetExGroupID());
	connection->Send(msg0s.ToJsonString());

	std::string msgBuffer;
	connection->Receive(msgBuffer);

	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(msgBuffer.c_str(), msgBuffer.c_str() + msgBuffer.size(), &jsonRoot, &errStr);

	return jsonRoot;
}

SGXClientRASession::SGXClientRASession(std::unique_ptr<Connection>& connection, SGXEnclave& enclave) :
	SGXClientRASession(connection, enclave, SendAndReceiveHandshakeMsg(connection, enclave))
{
}

SGXClientRASession::SGXClientRASession(std::unique_ptr<Connection>& connection, SGXEnclave & enclave, const Json::Value & jsonMsg) :
	SGXClientRASession(connection, enclave, ParseHandshakeMsg(jsonMsg))
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

	sgx_ra_context_t raContextID = 0;
	sgx_ra_msg1_t msg1Data;

	enclaveRes = m_sgxEnclave.ProcessRAMsg0Resp(k_remoteSideID, k_remoteSideSignKey, false, raContextID, msg1Data);
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRASPErrMsg errMsg(k_raSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	SGXRAMessage1 msg1(k_raSenderID, msg1Data);

	m_connection->Send(msg1.ToJsonString());
	m_connection->Receive(msgBuffer);
	auto msg2 = ParseMessageExpected<SGXRAMessage2>(msgBuffer);
	if (!msg2)
	{
		SGXRASPErrMsg errMsg(k_raSenderID, "Wrong response message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	std::vector<uint8_t> msg3Data;
	enclaveRes = m_sgxEnclave.ProcessRAMsg2(msg2->GetSenderID(), msg2->GetMsg2Data(), msg3Data, raContextID);
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRASPErrMsg errMsg(k_raSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		delete msg2;
		return false;
	}

	//Clean Message 2 (Message 1 response).
	delete msg2;
	msg2 = nullptr;

	SGXRAMessage3 msg3(k_raSenderID, msg3Data);

	m_connection->Send(msg3.ToJsonString());
	m_connection->Receive(msgBuffer);
	auto msg4 = ParseMessageExpected<SGXRAMessage4>(msgBuffer);
	if (!msg4)
	{
		SGXRASPErrMsg errMsg(k_raSenderID, "Wrong response message!");
		m_connection->Send(errMsg.ToJsonString());
		delete msg4;
		return false;
	}
	enclaveRes = m_sgxEnclave.ProcessRAMsg4(msg4->GetSenderID(), msg4->GetMsg4Data(), msg4->GetMsg4Signature(), raContextID);
	if (enclaveRes != SGX_SUCCESS)
	{
		delete msg4;
		return false;
	}

	//Clean Message 4 (Message 3 response).
	delete msg4;
	msg4 = nullptr;

	return true;
}
