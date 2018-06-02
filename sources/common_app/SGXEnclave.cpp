#include "SGXEnclave.h"

#include <sgx_urts.h>
#include <sgx_uae_service.h>

#include <boost/filesystem/operations.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "Common.h"
#include "../common/CryptoTools.h"
#include "SGXRemoteAttestationServer.h"
#include "SGXRemoteAttestationSession.h"
#include "SGXRAMessages/SGXRAMessage0.h"
#include "SGXRAMessages/SGXRAMessage1.h"
#include "SGXRAMessages/SGXRAMessage2.h"
#include "SGXRAMessages/SGXRAMessage3.h"

using namespace boost::asio;

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
	SGXRemoteAttestationSession RASession(ipAddr, portNum);
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

	SGXRAMessage0Send msg0s(msgSenderID, extended_epid_group_id);
	RAMessages* resp = RASession.SendMessages(msg0s);
	SGXRAMessage0Resp* msg0r = nullptr;
	if (!resp || !(msg0r = dynamic_cast<SGXRAMessage0Resp*>(resp)))
	{
		return false;
	}
	sgx_ec256_public_t spRAPubKey;
	DeserializePubKey(msg0r->GetRAPubKey(), spRAPubKey);
	res = SetRARemotePublicKey(spRAPubKey);
	if (res != SGX_SUCCESS)
	{
		return false;
	}
	sgx_ra_context_t raContextID = 0;
	res = EnclaveInitRA(false, raContextID);
	if (res != SGX_SUCCESS)
	{
		return false;
	}

	//Clean Message 0 response.
	delete resp;
	resp = nullptr;
	msg0r = nullptr;

	sgx_ra_msg1_t msg1data;
	res = GetRAMsg1(msg1data, raContextID);
	if (res != SGX_SUCCESS)
	{
		return false;
	}
	SGXRAMessage1 msg1(msgSenderID, msg1data);

	resp = RASession.SendMessages(msg1);
	SGXRAMessage2* msg2 = nullptr;
	if (!resp || !(msg2 = dynamic_cast<SGXRAMessage2*>(resp)))
	{
		return false;
	}
	sgx_ra_msg3_t msg3Data;
	std::vector<uint8_t> quote;
	ProcessMsg2(msg2->GetMsg2Data(), sizeof(sgx_ra_msg2_t)+ msg2->GetMsg2Data().sig_rl_size, msg3Data, quote, raContextID);

	//Clean Message 2 (Message 1 response).
	delete resp;
	resp = nullptr;
	msg2 = nullptr;

	SGXRAMessage3 msg3(msgSenderID, msg3Data, quote);

	resp = RASession.SendMessages(msg3);

	//Clean Message 4 (Message 3 response).
	delete resp;
	resp = nullptr;

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
			//TODO: verification here.
			return new SGXRAMessage0Resp(msgSenderID, true, msgSenderID);
		}
		case SGXRAMessage::Type::MSG1_SEND:
		{
			const SGXRAMessage1* msg1 = dynamic_cast<const SGXRAMessage1*>(sgxMsg);
			sgx_ra_msg2_t msg2Data;
			sgx_status_t res = this->ProcessMsg1(msg1->GetMsg1Data(), msg2Data);
			if (res != SGX_SUCCESS)
			{
				return new SGXRAMessage0Resp(msgSenderID, false, "");
			}
			return new SGXRAMessage2(msgSenderID, msg2Data, msg1->GetMsg1Data().gid);
		}
		case SGXRAMessage::Type::MSG3_SEND:
		{
			const SGXRAMessage3* msg3 = dynamic_cast<const SGXRAMessage3*>(sgxMsg);
			
			return new SGXRAMessage0Resp(msgSenderID, false, "");
		}
		default:
			return nullptr;
		}
	};
	
	bool res = false;
	//Message 0 from client:
	res = session->RecvMessages(msgProcessor);
	//Message 1 from client:
	res = session->RecvMessages(msgProcessor);
	//Message 3 from client:
	res = session->RecvMessages(msgProcessor);

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
