#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#include "SGXLASession.h"

#include <json/json.h>

#include <sgx_dh.h>

#include "SGXEnclave.h"
#include "SGXMessages/SGXLAMessage.h"
#include "../../common/DataCoding.h"
#include "../../common/JsonTools.h"
#include "../Networking/Connection.h"
#include "../MessageException.h"

template<class T>
static inline T*  ParseMessageExpected(const Json::Value& json)
{
	static_assert(std::is_base_of<SGXLAMessage, T>::value, "Class type must be a child class of SGXLAMessage.");

	SGXLAMessage::ParseCat(json); //Make sure it's a smart message. Otherwise a ParseException will be thrown.

	if (SGXLAMessage::ParseType(json[Messages::sk_LabelRoot]) == SGXLAErrMsg::sk_ValueType)
	{
		throw ReceivedErrorMessageException();
	}

	return new T(json);
}

bool SGXLASession::SendHandshakeMessage(std::unique_ptr<Connection>& connection, SGXEnclave & enclave)
{
	if (!connection)
	{
		return false;
	}
	sgx_ec256_public_t signPubKey;
	enclave.GetRAClientSignPubKey(signPubKey);
	std::string senderID = SerializePubKey(signPubKey);

	SGXLARequest reqMsg(senderID);
	connection->Send(reqMsg);

	return true;
}

bool SGXLASession::SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, SGXEnclave & enclave, const Json::Value & msg)
{
	if (SGXLAMessage::ParseType(msg[Messages::sk_LabelRoot]) == SGXLARequest::sk_ValueType)
	{
		SGXLARequest reqMsg(msg);
		SGXLASession laSession(connection, enclave, reqMsg);
		bool res = laSession.PerformResponderSideLA();
		laSession.SwapConnection(connection);
		return res;
	}
	else if (SGXLAMessage::ParseType(msg[Messages::sk_LabelRoot]) == SGXLAMessage1::sk_ValueType)
	{
		SGXLAMessage1* msg1 = new SGXLAMessage1(msg);
		SGXLASession laSession(connection, enclave, msg1);
		bool res = laSession.PerformInitiatorSideLA();
		laSession.SwapConnection(connection);
		return res;
	}
	return false;
}

static inline const SGXLAMessage1* SendAndReceiveHandshakeMsg(std::unique_ptr<Connection>& connection, SGXEnclave& enclave)
{
	SGXLASession::SendHandshakeMessage(connection, enclave);

	Json::Value jsonRoot;
	connection->Receive(jsonRoot);

	SGXLAMessage1* msg1 = ParseMessageExpected<SGXLAMessage1>(jsonRoot);

	return msg1;
}

SGXLASession::SGXLASession(std::unique_ptr<Connection>& connection, SGXEnclave & enclave) :
	SGXLASession(connection, enclave, SendAndReceiveHandshakeMsg(connection, enclave))
{
}

SGXLASession::SGXLASession(std::unique_ptr<Connection>& connection, SGXEnclave & enclave, const SGXLARequest & msg) :
	LocalAttestationSession(connection, enclave),
	k_remoteSideID(msg.GetSenderID())
{
}

SGXLASession::SGXLASession(std::unique_ptr<Connection>& connection, SGXEnclave & enclave, const SGXLAMessage1* msg) :
	LocalAttestationSession(connection, enclave),
	k_remoteSideID(msg->GetSenderID()),
	m_initorMsg1(msg)
{
}

SGXLASession::~SGXLASession()
{
}

bool SGXLASession::PerformInitiatorSideLA()
{
	if (!m_connection || !m_initorMsg1)
	{
		return false;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;

	std::unique_ptr<sgx_dh_msg2_t> msg2Data(std::make_unique<sgx_dh_msg2_t>());
	enclaveRet = m_hwEnclave.InitiatorProcessLAMsg1(k_remoteSideID, m_initorMsg1->GetData(), *msg2Data);
	if (enclaveRet != SGX_SUCCESS)
	{
		m_connection->Send(SGXLAErrMsg(k_raSenderID, "Enclave process error!"));
		return false;
	}

	SGXLAMessage2 msg2(k_raSenderID, msg2Data);
	m_connection->Send(msg2);

	Json::Value jsonRoot;
	m_connection->Receive(jsonRoot);

	try
	{
		std::unique_ptr<SGXLAMessage3> msg3(ParseMessageExpected<SGXLAMessage3>(jsonRoot));
		enclaveRet = m_hwEnclave.InitiatorProcessLAMsg3(k_remoteSideID, msg3->GetData());
		if (enclaveRet != SGX_SUCCESS)
		{
			m_connection->Send(SGXLAErrMsg(k_raSenderID, "Enclave process error!"));
			return false;
		}
	}
	catch (const MessageParseException&)
	{
		m_connection->Send(SGXLAErrMsg(k_raSenderID, "Received unexpected message! Make sure you are following the protocol."));
		return false;
	}

	return true;
}

bool SGXLASession::PerformResponderSideLA()
{
	if (!m_connection || m_initorMsg1)
	{
		return false;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;

	std::unique_ptr<sgx_dh_msg1_t> msg1Data(std::make_unique<sgx_dh_msg1_t>());
	enclaveRet = m_hwEnclave.ResponderGenerateLAMsg1(k_remoteSideID, *msg1Data);
	if (enclaveRet != SGX_SUCCESS)
	{
		m_connection->Send(SGXLAErrMsg(k_raSenderID, "Enclave process error!"));
		return false;
	}

	SGXLAMessage1 msg1(k_raSenderID, msg1Data);
	m_connection->Send(msg1);

	Json::Value jsonRoot;
	m_connection->Receive(jsonRoot);

	try
	{
		std::unique_ptr<SGXLAMessage2> msg2(ParseMessageExpected<SGXLAMessage2>(jsonRoot));

		std::unique_ptr<sgx_dh_msg3_t> msg3Data(std::make_unique<sgx_dh_msg3_t>());
		enclaveRet = m_hwEnclave.ResponderProcessLAMsg2(k_remoteSideID, msg2->GetData(), *msg3Data);
		if (enclaveRet != SGX_SUCCESS)
		{
			m_connection->Send(SGXLAErrMsg(k_raSenderID, "Enclave process error!"));
			return false;
		}

		SGXLAMessage3 msg3(k_raSenderID, msg3Data);
		m_connection->Send(msg3);
	}
	catch (const MessageParseException&)
	{
		m_connection->Send(SGXLAErrMsg(k_raSenderID, "Received unexpected message! Make sure you are following the protocol."));
		return false;
	}


	return true;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
