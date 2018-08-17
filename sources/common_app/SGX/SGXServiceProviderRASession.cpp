#include "SGXServiceProviderRASession.h"

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
#include "SGXRAMessages/SGXRAMessageErr.h"

namespace
{
	std::vector<uint32_t> g_acceptedExGID =
	{
		0,
	};

	std::map<std::string, SGXRAMessage::Type> g_msgTypeNameMap =
	{
		std::pair<std::string, SGXRAMessage::Type>("MSG0_SEND", SGXRAMessage::Type::MSG0_SEND),
		std::pair<std::string, SGXRAMessage::Type>("MSG0_RESP", SGXRAMessage::Type::MSG0_RESP),
		std::pair<std::string, SGXRAMessage::Type>("MSG1_SEND", SGXRAMessage::Type::MSG1_SEND),
		std::pair<std::string, SGXRAMessage::Type>("MSG2_RESP", SGXRAMessage::Type::MSG2_RESP),
		std::pair<std::string, SGXRAMessage::Type>("MSG3_SEND", SGXRAMessage::Type::MSG3_SEND),
		std::pair<std::string, SGXRAMessage::Type>("MSG4_RESP", SGXRAMessage::Type::MSG4_RESP),
		std::pair<std::string, SGXRAMessage::Type>("ERRO_RESP", SGXRAMessage::Type::ERRO_RESP),
		std::pair<std::string, SGXRAMessage::Type>("OTHER", SGXRAMessage::Type::OTHER),
	};
}

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

	auto it = g_msgTypeNameMap.find(jsonRoot["MsgSubType"].asString());
	if (it == g_msgTypeNameMap.end() || it->second == SGXRAMessage::Type::OTHER)
	{
		LOGI("Recv INVALID MESSAGE!");
		return nullptr;
	}

	switch (it->second)
	{
	case SGXRAMessage::Type::MSG0_SEND:
		return new SGXRAMessage0Send(jsonRoot);
	case SGXRAMessage::Type::MSG0_RESP:
		return new SGXRAMessage0Resp(jsonRoot);
	case SGXRAMessage::Type::MSG1_SEND:
		return new SGXRAMessage1(jsonRoot);
	case SGXRAMessage::Type::MSG2_RESP:
		return new SGXRAMessage2(jsonRoot);
	case SGXRAMessage::Type::MSG3_SEND:
		return new SGXRAMessage3(jsonRoot);
	case SGXRAMessage::Type::MSG4_RESP:
		return new SGXRAMessage4(jsonRoot);
	case SGXRAMessage::Type::ERRO_RESP:
		return new SGXRAMessageErr(jsonRoot);
	default:
		return nullptr;
	}
}

SGXServiceProviderRASession::SGXServiceProviderRASession(std::unique_ptr<Connection>& connection, SGXServiceProvider & serviceProviderBase, IASConnector & ias) :
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

	RAMessages* reqs = nullptr;
	SGXRAMessage* resp = nullptr;
	std::string msgBuffer;
	std::string msgSenderID = GetSenderID();

	m_connection->Receive(msgBuffer);
	reqs = JsonMessageParser(msgBuffer);

	SGXRAMessage0Send* msg0s = dynamic_cast<SGXRAMessage0Send*>(reqs);
	if (!reqs || !msg0s || !msg0s->IsValid())
	{
		SGXRAMessageErr errMsg(msgSenderID, "Wrong request message!");
		m_connection->Send(errMsg.ToJsonString());
		delete reqs;
		return false;
	}

	if (std::find(g_acceptedExGID.begin(), g_acceptedExGID.end(), msg0s->GetExtendedGroupID()) != g_acceptedExGID.end())
	{
		enclaveRes = m_sgxSP.ProcessRAMsg0Send(msg0s->GetSenderID());
		if (enclaveRes != SGX_SUCCESS)
		{
			SGXRAMessageErr errMsg(msgSenderID, "Enclave process error!");
			m_connection->Send(errMsg.ToJsonString());
			delete reqs;
			return false;
		}
		else
		{
			resp = new SGXRAMessage0Resp(msgSenderID, msgSenderID);
		}
	}
	else
	{
		SGXRAMessageErr errMsg(msgSenderID, "Extended Group ID is not accepted!");
		m_connection->Send(errMsg.ToJsonString());
		delete reqs;
		return false;
	}

	m_connection->Send(resp->ToJsonString());
	delete resp;
	resp = nullptr;
	delete reqs;
	reqs = nullptr;
	msg0s = nullptr;

	m_connection->Receive(msgBuffer);
	reqs = JsonMessageParser(msgBuffer);

	SGXRAMessage1* msg1 = dynamic_cast<SGXRAMessage1*>(reqs);
	if (!reqs || !msg1 || !msg1->IsValid())
	{
		SGXRAMessageErr errMsg(msgSenderID, "Wrong request message!");
		m_connection->Send(errMsg.ToJsonString());
		delete reqs;
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
		SGXRAMessageErr errMsg(msgSenderID, "Failed to get Revocation List!");
		m_connection->Send(errMsg.ToJsonString());
		delete reqs;
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
		SGXRAMessageErr errMsg(msgSenderID, "Extended Group ID is not accepted!");
		m_connection->Send(errMsg.ToJsonString());
		delete reqs;
		return false;
	}
	msg2Ref.sig_rl_size = static_cast<uint32_t>(sigRLData.size());
	std::memcpy(msg2Data.data() + sizeof(sgx_ra_msg2_t), sigRLData.data(), sigRLData.size());
	resp = new SGXRAMessage2(msgSenderID, msg2Data);

	m_connection->Send(resp->ToJsonString());
	delete resp;
	resp = nullptr;
	delete reqs;
	reqs = nullptr;
	msg1 = nullptr;

	m_connection->Receive(msgBuffer);
	reqs = JsonMessageParser(msgBuffer);

	SGXRAMessage3* msg3 = dynamic_cast<SGXRAMessage3*>(reqs);
	if (!reqs || !msg3 || !msg3->IsValid())
	{
		SGXRAMessageErr errMsg(msgSenderID, "Wrong request message!");
		m_connection->Send(errMsg.ToJsonString());
		delete reqs;
		return false;
	}

	sgx_ra_msg4_t msg4Data;
	sgx_ec256_signature_t msg4Sign;
	
	std::string iasNonce;
	enclaveRes = m_sgxSP.GetIasReportNonce(msg3->GetSenderID(), iasNonce);
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRAMessageErr errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		delete reqs;
		return false;
	}

	Json::Value iasReqRoot;
	iasReqRoot["isvEnclaveQuote"] = msg3->GetQuoteBase64();
	iasReqRoot["nonce"] = iasNonce;
	std::string iasReport;
	std::string iasReportSign;
	std::string iasCert;
	m_ias.GetQuoteReport(iasReqRoot.toStyledString(), iasReport, iasReportSign, iasCert);
	enclaveRes = m_sgxSP.ProcessRAMsg3(msg3->GetSenderID(), msg3->GetMsg3Data(), iasReport, iasReportSign, iasCert, msg4Data, msg4Sign);
	if (enclaveRes != SGX_SUCCESS)
	{
		SGXRAMessageErr errMsg(msgSenderID, "Enclave process error!");
		m_connection->Send(errMsg.ToJsonString());
		delete reqs;
		return false;
	}
	resp = new SGXRAMessage4(msgSenderID, msg4Data, msg4Sign);

	m_connection->Send(resp->ToJsonString());
	delete resp;
	resp = nullptr;
	delete reqs;
	reqs = nullptr;
	msg3 = nullptr;

	return true;
}
