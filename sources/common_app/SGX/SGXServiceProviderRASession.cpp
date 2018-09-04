#include "SGXServiceProviderRASession.h"

#include <type_traits>

#include <json/json.h>

#include "../../common/DataCoding.h"
#include "../../common/JsonTools.h"
#include "../../common/SGX/ias_report.h"

#include "../Common.h"

#include "../Networking/Connection.h"

#include "SGXServiceProviderBase.h"

#include "IAS/IASConnector.h"

#include "SGXMessages/SGXRAMessage.h"
#include "SGXMessages/SGXRAMessage0.h"
#include "SGXMessages/SGXRAMessage1.h"
#include "SGXMessages/SGXRAMessage2.h"
#include "SGXMessages/SGXRAMessage3.h"
#include "SGXMessages/SGXRAMessage4.h"

#include "../MessageException.h"

namespace
{
	const std::vector<uint32_t> g_acceptedExGID =
	{
		0,
	};
}

template<class T>
static T*  ParseMessageExpected(const Json::Value& json)
{
	static_assert(std::is_base_of<SGXRASPMessage, T>::value, "Class type must be a child class of SGXRASPMessage.");
	
	SGXRASPMessage::ParseCat(json); //Make sure it's a smart message. Otherwise a ParseException will be thrown.

	if (SGXRASPMessage::ParseType(json[Messages::sk_LabelRoot]) == SGXRASPErrMsg::sk_ValueType)
	{
		throw ReceivedErrorMessageException();
	}
	
	return new T(json);
}

template<class T>
static T* ParseMessageExpected(const std::string& jsonStr)
{
	static_assert(std::is_base_of<SGXRASPMessage, T>::value, "Class type must be a child class of SGXRASPMessage.");

	Json::Value jsonRoot;
	if (!ParseStr2Json(jsonRoot, jsonStr))
	{
		throw MessageParseException();
	}

	return ParseMessageExpected<T>(jsonRoot);
}

static std::string ProcessHandshakeMsg(const SGXRAMessage0Send & msg0s)
{
	if (std::find(g_acceptedExGID.begin(), g_acceptedExGID.end(), msg0s.GetExtendedGroupID()) == g_acceptedExGID.end())
	{
		throw MessageInvalidException();
	}

	std::string res;
	res = msg0s.GetSenderID();
	return res;
}

static const Json::Value ReceiveHandshakeMsg(std::unique_ptr<Connection>& connection)
{
	std::string msgBuffer;
	connection->Receive(msgBuffer);

	Json::Value jsonRoot;
	if (!ParseStr2Json(jsonRoot, msgBuffer))
	{
		throw MessageParseException();
	}

	return jsonRoot;
}

bool SGXServiceProviderRASession::SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, SGXServiceProviderBase & serviceProviderBase, const IASConnector & ias, const Json::Value & jsonMsg)
{
	if (SGXRASPMessage::ParseType(jsonMsg[Messages::sk_LabelRoot]) == SGXRAMessage0Send::sk_ValueType)
	{
		SGXRAMessage0Send msg0s(jsonMsg);
		SGXServiceProviderRASession raSession(connection, serviceProviderBase, ias, msg0s);
		bool res = raSession.ProcessServerSideRA();
		raSession.SwapConnection(connection);
		return res;
	}
	return false;
}

SGXServiceProviderRASession::SGXServiceProviderRASession(std::unique_ptr<Connection>& connection, SGXServiceProviderBase & serviceProviderBase, const IASConnector & ias) :
	SGXServiceProviderRASession(connection, serviceProviderBase, ias, ReceiveHandshakeMsg(connection))
{
}

SGXServiceProviderRASession::SGXServiceProviderRASession(std::unique_ptr<Connection>& connection, SGXServiceProviderBase & serviceProviderBase, const IASConnector & ias, const SGXRAMessage0Send & msg0s) :
	k_senderId(serviceProviderBase.GetRASPSignPubKey()),
	k_remoteSideId(ProcessHandshakeMsg(msg0s)),
	m_sgxSP(serviceProviderBase),
	m_ias(ias)
{
	//At this point, everything went well, no exeception thrown. Now acquire the connection.
	m_connection.swap(connection);
}

SGXServiceProviderRASession::~SGXServiceProviderRASession()
{
}

bool SGXServiceProviderRASession::ProcessServerSideRA()
{
	if (!m_connection)
	{
		return false;
	}
	sgx_status_t enclaveRes = SGX_SUCCESS;
	std::string msgBuffer;

	try
	{
		SGXRAClientErrMsg enclaveErrMsg(k_senderId, "Enclave process error!");
		sgx_ec256_public_t clientPubSignKey;
		DeserializeStruct(clientPubSignKey, k_remoteSideId);

		SGXRAMessage0Resp msg0r(k_senderId, k_senderId);
		m_connection->Send(msg0r.ToJsonString());

		m_connection->Receive(msgBuffer);
		std::unique_ptr<SGXRAMessage1> msg1(ParseMessageExpected<SGXRAMessage1>(msgBuffer));

		std::string sigRlStr;
		int32_t respCode = 0;

		respCode = m_ias.GetRevocationList(msg1->GetMsg1Data().gid, sigRlStr);
		if (respCode != 200)
		{
			SGXRAClientErrMsg errMsg(k_senderId, "Failed to get Revocation List from IAS!");
			m_connection->Send(errMsg.ToJsonString());
			return false;
		}

		std::vector<uint8_t> sigRLData;
		DeserializeStruct(sigRLData, sigRlStr);
		std::vector<uint8_t> msg2Data;
		msg2Data.resize(sizeof(sgx_ra_msg2_t) + sigRLData.size());
		sgx_ra_msg2_t& msg2Ref = *reinterpret_cast<sgx_ra_msg2_t*>(msg2Data.data());

		enclaveRes = m_sgxSP.ProcessRAMsg1(msg1->GetSenderID(), clientPubSignKey, msg1->GetMsg1Data(), msg2Ref);
		if (enclaveRes != SGX_SUCCESS)
		{
			m_connection->Send(enclaveErrMsg);
			return false;
		}
		msg2Ref.sig_rl_size = static_cast<uint32_t>(sigRLData.size());
		std::memcpy(msg2Data.data() + sizeof(sgx_ra_msg2_t), sigRLData.data(), sigRLData.size());

		SGXRAMessage2 msg2(k_senderId, msg2Data);
		m_connection->Send(msg2.ToJsonString());

		m_connection->Receive(msgBuffer);
		std::unique_ptr<SGXRAMessage3> msg3(ParseMessageExpected<SGXRAMessage3>(msgBuffer));

		sgx_ias_report_t msg4Data;
		sgx_ec256_signature_t msg4Sign;
	
		std::string iasNonce;
		enclaveRes = m_sgxSP.GetIasReportNonce(msg3->GetSenderID(), iasNonce);
		if (enclaveRes != SGX_SUCCESS)
		{
			m_connection->Send(enclaveErrMsg);
			return false;
		}

		Json::Value iasReqRoot;
		iasReqRoot["isvEnclaveQuote"] = msg3->GetQuoteBase64();
		iasReqRoot["nonce"] = iasNonce;
		std::string iasReport;
		std::string iasReportSign;
		std::string iasCert;

		respCode = m_ias.GetQuoteReport(iasReqRoot.toStyledString(), iasReport, iasReportSign, iasCert);
		if (respCode != 200)
		{
			SGXRAClientErrMsg errMsg(k_senderId, "Failed to get report from IAS!");
			m_connection->Send(errMsg.ToJsonString());
			return false;
		}

		enclaveRes = m_sgxSP.ProcessRAMsg3(msg3->GetSenderID(), msg3->GetMsg3Data(), iasReport, iasReportSign, iasCert, msg4Data, msg4Sign);
		if (enclaveRes != SGX_SUCCESS)
		{
			m_connection->Send(enclaveErrMsg);
			return false;
		}

		SGXRAMessage4 msg4(k_senderId, msg4Data, msg4Sign);
		m_connection->Send(msg4.ToJsonString());

		return true;
	}
	catch (const MessageParseException&)
	{
		SGXRAClientErrMsg errMsg(k_senderId, "Received unexpected message! Make sure you are following the protocol.");
		m_connection->Send(errMsg);
		return false;
	}
}
