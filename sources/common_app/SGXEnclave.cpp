#include "SGXEnclave.h"

#include <sgx_urts.h>
#include <sgx_uae_service.h>

#include <boost/filesystem/operations.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "Common.h"
#include "SGXRemoteAttestationServer.h"
#include "SGXRemoteAttestationSession.h"
#include "SGXRAMessages/SGXRAMessage0.h"

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
	uint32_t extended_epid_group_id = 0;
	sgx_status_t res = sgx_get_extended_epid_group_id(&extended_epid_group_id);
	if (res != SGX_SUCCESS)
	{
		return false;
	}
	SGXRAMessage0Send msg0s(extended_epid_group_id);
	RAMessages* resp = RASession.SendMessages(msg0s);
	SGXRAMessage0Resp* msg0r = nullptr;
	if (!resp || !(msg0r = dynamic_cast<SGXRAMessage0Resp*>(resp)))
	{
		return false;
	}
	delete resp;
	resp = nullptr;
	msg0r = nullptr;

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
	SGXRemoteAttestationSession* session = dynamic_cast<SGXRemoteAttestationSession*>(m_raServer->AcceptRAConnection());
	RemoteAttestationSession::MsgProcessor msgProcessor = [](const RAMessages* msg) -> RAMessages*
	{
		const SGXRAMessage* sgxMsg = dynamic_cast<const SGXRAMessage*>(msg);
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
			return new SGXRAMessage0Resp(true);
		}
		default:
			return nullptr;
		}
	};
	bool res = session->RecvMessages(msgProcessor);

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
