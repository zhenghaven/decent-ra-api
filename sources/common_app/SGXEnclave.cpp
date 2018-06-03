#include "SGXEnclave.h"

#include <algorithm>

#include <sgx_urts.h>
#include <sgx_uae_service.h>

#include <boost/filesystem/operations.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "Common.h"
#include "../common/CryptoTools.h"
#include "../common/sgx_ra_msg4.h"

#include "SGXRemoteAttestationServer.h"
#include "SGXRemoteAttestationSession.h"
#include "SGXRAMessages/SGXRAMessage0.h"
#include "SGXRAMessages/SGXRAMessage1.h"
#include "SGXRAMessages/SGXRAMessage2.h"
#include "SGXRAMessages/SGXRAMessage3.h"
#include "SGXRAMessages/SGXRAMessage4.h"
#include "SGXRAMessages/SGXRAMessageErr.h"

using namespace boost::asio;

namespace
{
	std::vector<uint32_t> g_acceptedExGID = 
	{
		0,
	};
}

SGXEnclave::SGXEnclave(const std::string enclavePath, const std::string tokenPath) :
	SGXEnclave(enclavePath, fs::path(tokenPath))
{
	
}

SGXEnclave::SGXEnclave(const std::string enclavePath, const fs::path tokenPath) :
	m_eid(0),
	m_lastStatus(SGX_SUCCESS),
	m_token(0),
	m_enclavePath(enclavePath),
	m_tokenPath(tokenPath),
	m_raServer(nullptr)
{
}

SGXEnclave::SGXEnclave(const std::string enclavePath, const KnownFolderType tokenLocType, const std::string tokenFileName) :
	SGXEnclave(enclavePath, GetKnownFolderPath(tokenLocType).append(tokenFileName))
{
	fs::path tokenFolder = m_tokenPath.parent_path();
	fs::create_directories(tokenFolder);
}

SGXEnclave::~SGXEnclave()
{
	if (IsLaunched())
	{
		sgx_destroy_enclave(m_eid);
	}
	if (m_raServer)
	{
		delete m_raServer;
	}
}

bool SGXEnclave::Launch()
{
	int needUpdateToken = 0;
	sgx_launch_token_t token = { 0 };
	if (!LoadToken())
	{
		LOGW("Enclave App - %s, Read token from %s Failed!", m_enclavePath.c_str(), m_tokenPath.string().c_str());
	}
	else 
	{
		memcpy(token, m_token.data(), m_token.size());
	}
	sgx_status_t createRes = sgx_create_enclave(m_enclavePath.c_str(), SGX_DEBUG_FLAG, &token, &needUpdateToken, &m_eid, NULL);
	if (createRes != SGX_SUCCESS)
	{
		m_lastStatus = createRes;
		m_eid = 0;
		return false;
	}
	if (needUpdateToken)
	{
		m_token.resize(sizeof(sgx_launch_token_t), 0);
		memcpy(&m_token[0], token, m_token.size());
		if (!UpdateToken())
		{
			LOGW("Enclave App - %s, Write token to %s Failed!", m_enclavePath.c_str(), m_tokenPath.string().c_str());
		}
	}
	return true;
}

bool SGXEnclave::IsLastExecutionFailed() const
{
	return (m_lastStatus != SGX_SUCCESS);
}

bool SGXEnclave::IsLaunched() const
{
	return (m_eid != 0);
}

bool SGXEnclave::RequestRA(uint32_t ipAddr, uint16_t portNum)
{
	sgx_status_t res = SGX_SUCCESS;

	//Get extended group ID.
	uint32_t extended_epid_group_id = 0;
	res = sgx_get_extended_epid_group_id(&extended_epid_group_id);
	if (res != SGX_SUCCESS)
	{
		return false;
	}

	//Get Sign public key.
	sgx_ec256_public_t signPubKey;
	res = GetRAPublicKey(signPubKey);
	if (res != SGX_SUCCESS)
	{
		return false;
	}
	std::string msgSenderID = SerializePubKey(signPubKey);

	//Now ready to connect...
	SGXRemoteAttestationSession RASession(ipAddr, portNum);

	SGXRAMessage0Send msg0s(msgSenderID, extended_epid_group_id);
	RAMessages* resp = RASession.SendMessages(msgSenderID, msg0s);
	if (!resp)
	{
		return false;
	}
	SGXRAMessage0Resp* msg0r = nullptr;
	if (!resp || !(msg0r = dynamic_cast<SGXRAMessage0Resp*>(resp)))
	{
		delete resp;
		RASession.SendErrorMessages(SGXRAMessageErr(msgSenderID, "Wrong response message!"));
		return false;
	}

	sgx_ec256_public_t spRAPubKey;
	DeserializePubKey(msg0r->GetRAPubKey(), spRAPubKey);

	sgx_ra_context_t raContextID = 0;

	sgx_ra_msg1_t msg1Data;

	res = ProcessRAMsg0Resp(msg0r->GetSenderID(), spRAPubKey, false, raContextID, msg1Data);
	if (res != SGX_SUCCESS)
	{
		delete resp;
		RASession.SendErrorMessages(SGXRAMessageErr(msgSenderID, "Enclave process error!"));
		return false;
	}

	//Clean Message 0 response.
	delete resp;
	resp = nullptr;
	msg0r = nullptr;

	SGXRAMessage1 msg1(msgSenderID, msg1Data);

	resp = RASession.SendMessages(msgSenderID, msg1);
	if (!resp)
	{
		return false;
	}
	SGXRAMessage2* msg2 = nullptr;
	if (!resp || !(msg2 = dynamic_cast<SGXRAMessage2*>(resp)))
	{
		delete resp;
		RASession.SendErrorMessages(SGXRAMessageErr(msgSenderID, "Wrong response message!"));
		return false;
	}
	sgx_ra_msg3_t msg3Data;
	std::vector<uint8_t> quote;
	ProcessRAMsg2(msg2->GetSenderID(), msg2->GetMsg2Data(), sizeof(sgx_ra_msg2_t)+ msg2->GetMsg2Data().sig_rl_size, msg3Data, quote, raContextID);

	//Clean Message 2 (Message 1 response).
	delete resp;
	resp = nullptr;
	msg2 = nullptr;

	SGXRAMessage3 msg3(msgSenderID, msg3Data, quote);

	resp = RASession.SendMessages(msgSenderID, msg3);
	SGXRAMessage4* msg4 = nullptr;
	if (!resp || !(msg4 = dynamic_cast<SGXRAMessage4*>(resp)))
	{
		delete resp;
		RASession.SendErrorMessages(SGXRAMessageErr(msgSenderID, "Wrong response message!"));
		return false;
	}
	ProcessRAMsg4(msg4->GetSenderID(), msg4->GetMsg4Data(), msg4->GetMsg4Signature());

	//Clean Message 4 (Message 3 response).
	delete resp;
	resp = nullptr;
	msg4 = nullptr;

	return true;
}

void SGXEnclave::LaunchRAServer(uint32_t ipAddr, uint16_t portNum)
{
	m_raServer = new SGXRemoteAttestationServer(ipAddr, portNum);
}

bool SGXEnclave::IsRAServerLaunched() const
{
	return m_raServer;
}

bool SGXEnclave::AcceptRAConnection()
{
	sgx_status_t enclaveRes = SGX_SUCCESS;

	//Get Sign public key.
	sgx_ec256_public_t signPubKey;
	enclaveRes = GetRAPublicKey(signPubKey);
	if (enclaveRes != SGX_SUCCESS)
	{
		return false;
	}
	std::string msgSenderID = SerializePubKey(signPubKey);

	SGXRemoteAttestationSession* session = dynamic_cast<SGXRemoteAttestationSession*>(m_raServer->AcceptRAConnection());

	//Message Processor Lambda function:
	RemoteAttestationSession::MsgProcessor msgProcessor = [this, msgSenderID](const RAMessages& msg) -> RAMessages*
	{
		const SGXRAMessage* sgxMsg = dynamic_cast<const SGXRAMessage*>(&msg);
		if (!sgxMsg)
		{
			return nullptr;
		}

		switch (sgxMsg->GetType())
		{
		case SGXRAMessage::Type::MSG0_SEND:
		{
			const SGXRAMessage0Send* msg0s = dynamic_cast<const SGXRAMessage0Send*>(sgxMsg);
			if (std::find(g_acceptedExGID.begin(), g_acceptedExGID.end(), msg0s->GetExtendedGroupID()) != g_acceptedExGID.end())
			{
				sgx_status_t enclaveRes = SGX_SUCCESS;
				enclaveRes = ProcessRAMsg0Send(msg0s->GetSenderID());
				if (enclaveRes != SGX_SUCCESS)
				{
					return new SGXRAMessageErr(msgSenderID, "Enclave process error!");
				}
				return new SGXRAMessage0Resp(msgSenderID, msgSenderID);
				
			}
			else
			{
				return new SGXRAMessageErr(msgSenderID, "Extended Group ID is not accepted!");
			}
		}
		case SGXRAMessage::Type::MSG1_SEND:
		{
			const SGXRAMessage1* msg1 = dynamic_cast<const SGXRAMessage1*>(sgxMsg);
			sgx_ra_msg2_t msg2Data;
			sgx_status_t res = ProcessRAMsg1(msg1->GetSenderID(), msg1->GetMsg1Data(), msg2Data);
			if (res != SGX_SUCCESS)
			{
				return new SGXRAMessageErr(msgSenderID, "Enclave Process Error");
			}
			return new SGXRAMessage2(msgSenderID, msg2Data, msg1->GetMsg1Data().gid);
		}
		case SGXRAMessage::Type::MSG3_SEND:
		{
			const SGXRAMessage3* msg3 = dynamic_cast<const SGXRAMessage3*>(sgxMsg);
			sgx_ra_msg4_t msg4Data;
			sgx_ec256_signature_t msg4Sign;

			sgx_status_t enclaveRes = SGX_SUCCESS;
			enclaveRes = ProcessRAMsg3(msg3->GetSenderID(), msg3->GetMsg3Data(), msg3->GetMsg3DataSize(), "", "", msg4Data, msg4Sign);
			if (enclaveRes != SGX_SUCCESS)
			{
				return new SGXRAMessageErr(msgSenderID, "Enclave process error!");
			}

			return new SGXRAMessage4(msgSenderID, msg4Data, msg4Sign);
		}
		default:
			return nullptr;
		}
	};
	
	bool res = false;
	//Message 0 from client:
	res = session->RecvMessages(msgSenderID, msgProcessor);
	if (!res)
	{
		delete session;
		return res;
	}
	//Message 1 from client:
	res = session->RecvMessages(msgSenderID, msgProcessor);
	if (!res)
	{
		delete session;
		return res;
	}
	//Message 3 from client:
	res = session->RecvMessages(msgSenderID, msgProcessor);
	if (!res)
	{
		delete session;
		return res;
	}

	delete session;
	return res;
}

sgx_status_t SGXEnclave::GetLastStatus() const
{
	return m_lastStatus;
}

sgx_enclave_id_t SGXEnclave::GetEnclaveId() const
{
	return m_eid;
}

bool SGXEnclave::LoadToken()
{
	FileHandler tokenFile(m_tokenPath, FileHandler::Mode::Read);
	if (!tokenFile.Open())
	{
		return false;
	}
	bool readRes = tokenFile.ReadBlock(m_token, sizeof(sgx_launch_token_t));
	if (!readRes)
	{
		m_token.resize(0);
	}
	return readRes;
}

bool SGXEnclave::UpdateToken()
{
	FileHandler tokenFile(m_tokenPath, FileHandler::Mode::Write);
	if (!tokenFile.Open())
	{
		return false;
	}
	bool writeRes = tokenFile.WriteBlock(m_token);
	return writeRes;
}
