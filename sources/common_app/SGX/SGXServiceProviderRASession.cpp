#include "SGXServiceProviderRASession.h"

#include <type_traits>

#include <json/json.h>

#include "../../common/SGX/sgx_ra_msg4.h"
#include "../../common/DataCoding.h"

#include "../Common.h"

#include "../Networking/Connection.h"

#include "SGXServiceProvider.h"

#include "IAS/IASConnector.h"

#include "SGXRAMessages/SGXRAMessage.h"
#include "SGXRAMessages/SGXRAMessage0.h"
#include "SGXRAMessages/SGXRAMessage1.h"
#include "SGXRAMessages/SGXRAMessage2.h"
#include "SGXRAMessages/SGXRAMessage3.h"
#include "SGXRAMessages/SGXRAMessage4.h"

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
	try
	{
		std::string cat = SGXRASPMessage::ParseCat(json);
		if (cat != SGXRASPMessage::VALUE_CAT)
		{
			return nullptr;
		}

		std::string type = SGXRASPMessage::ParseType(json[Messages::LABEL_ROOT]);

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
	static_assert(std::is_base_of<SGXRASPMessage, T>::value, "Class type must be a child class of SGXRASPMessage.");

	Json::Value jsonRoot;
	Json::CharReaderBuilder rbuilder;
	rbuilder["collectComments"] = false;
	std::string errStr;

	const std::unique_ptr<Json::CharReader> reader(rbuilder.newCharReader());
	bool isValid = reader->parse(jsonStr.c_str(), jsonStr.c_str() + jsonStr.size(), &jsonRoot, &errStr);

	return ParseMessageExpected<T>(jsonRoot);
}

SGXServiceProviderRASession::SGXServiceProviderRASession(std::unique_ptr<Connection>& connection, SGXServiceProvider & serviceProviderBase, const IASConnector & ias) :
	ServiceProviderRASession(connection, serviceProviderBase),
	m_sgxSP(serviceProviderBase),
	m_ias(ias)
{
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
	std::string msgSenderID = GetSenderID();

	m_connection->Receive(msgBuffer);

	auto msg0s = ParseMessageExpected<SGXRAMessage0Send>(msgBuffer);
	if (!msg0s)
	{
		SGXRAClientErrMsg errMsg(msgSenderID, "Wrong request message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	if (std::find(g_acceptedExGID.begin(), g_acceptedExGID.end(), msg0s->GetExtendedGroupID()) == g_acceptedExGID.end())
	{
		SGXRAClientErrMsg errMsg(msgSenderID, "Extended Group ID is not accepted!");
		m_connection->Send(errMsg.ToJsonString());
		delete msg0s;
		return false;
	}

	enclaveRes = m_sgxSP.ProcessRAMsg0Send(msg0s->GetSenderID());
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRAClientErrMsg errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		delete msg0s;
		return false;
	}

	SGXRAMessage0Resp msg0r(msgSenderID, msgSenderID);

	m_connection->Send(msg0r.ToJsonString());
	delete msg0s;
	msg0s = nullptr;

	m_connection->Receive(msgBuffer);
	auto msg1 = ParseMessageExpected<SGXRAMessage1>(msgBuffer);
	if (!msg1)
	{
		SGXRAClientErrMsg errMsg(msgSenderID, "Wrong request message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	std::string sigRlStr;
	int32_t respCode = 0;

#ifdef SIMULATING_ENCLAVE
	respCode = 200;
#else
	respCode = m_ias.GetRevocationList(msg1->GetMsg1Data().gid, sigRlStr);
#endif // SIMULATING_ENCLAVE

	if (respCode != 200)
	{
		SGXRAClientErrMsg errMsg(msgSenderID, "Failed to get Revocation List!");
		m_connection->Send(errMsg.ToJsonString());
		delete msg1;
		return false;
	}

	std::vector<uint8_t> sigRLData;
	DeserializeStruct(sigRLData, sigRlStr);
	std::vector<uint8_t> msg2Data;
	msg2Data.resize(sizeof(sgx_ra_msg2_t) + sigRLData.size());
	sgx_ra_msg2_t& msg2Ref = *reinterpret_cast<sgx_ra_msg2_t*>(msg2Data.data());

	enclaveRes = m_sgxSP.ProcessRAMsg1(msg1->GetSenderID(), msg1->GetMsg1Data(), msg2Ref);
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRAClientErrMsg errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		delete msg1;
		return false;
	}
	msg2Ref.sig_rl_size = static_cast<uint32_t>(sigRLData.size());
	std::memcpy(msg2Data.data() + sizeof(sgx_ra_msg2_t), sigRLData.data(), sigRLData.size());
	SGXRAMessage2 msg2(msgSenderID, msg2Data);

	m_connection->Send(msg2.ToJsonString());
	delete msg1;
	msg1 = nullptr;

	m_connection->Receive(msgBuffer);
	auto msg3 = ParseMessageExpected<SGXRAMessage3>(msgBuffer);

	if (!msg3)
	{
		SGXRAClientErrMsg errMsg(msgSenderID, "Wrong request message!");
		m_connection->Send(errMsg.ToJsonString());
		return false;
	}

	sgx_ra_msg4_t msg4Data;
	sgx_ec256_signature_t msg4Sign;
	
	std::string iasNonce;
	enclaveRes = m_sgxSP.GetIasReportNonce(msg3->GetSenderID(), iasNonce);
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRAClientErrMsg errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		delete msg3;
		return false;
	}

	Json::Value iasReqRoot;
	iasReqRoot["isvEnclaveQuote"] = msg3->GetQuoteBase64();
	iasReqRoot["nonce"] = iasNonce;
	std::string iasReport;
	std::string iasReportSign;
	std::string iasCert;
	/*TODO: Simulation code here: */
	respCode = m_ias.GetQuoteReport(iasReqRoot.toStyledString(), iasReport, iasReportSign, iasCert);
	enclaveRes = m_sgxSP.ProcessRAMsg3(msg3->GetSenderID(), msg3->GetMsg3Data(), iasReport, iasReportSign, iasCert, msg4Data, msg4Sign);
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRAClientErrMsg errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		delete msg3;
		return false;
	}
	SGXRAMessage4 msg4(msgSenderID, msg4Data, msg4Sign);

	m_connection->Send(msg4.ToJsonString());
	delete msg3;
	msg3 = nullptr;

	return true;
}
