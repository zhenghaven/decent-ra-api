#include "SGXEnclave.h"

#include <algorithm>

#include <sgx_urts.h>
#include <sgx_uae_service.h>

#include <boost/filesystem/operations.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "../common/CryptoTools.h"
#include "../common/sgx_ra_msg4.h"

#include "Common.h"
#include "SGXRemoteAttestationServer.h"
#include "SGXRemoteAttestationSession.h"

#include "Networking/Connection.h"

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
	m_raServer(nullptr),
	m_raSenderID(),
	m_exGroupID(0)
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

std::unique_ptr<Connection> SGXEnclave::RequestRA(uint32_t ipAddr, uint16_t portNum)
{
	std::unique_ptr<Connection> connection(std::make_unique<Connection>(ipAddr, portNum));
	SGXRemoteAttestationSession RASession(connection, RemoteAttestationSession::Mode::Client);
	bool res = RASession.ProcessClientSideRA(*this);
	
	return res ? RASession.ReleaseConnection() : nullptr;
}

std::string SGXEnclave::GetRASenderID() const
{
	return m_raSenderID;
}

uint32_t SGXEnclave::GetExGroupID() const
{
	return m_exGroupID;
}

void SGXEnclave::LaunchRAServer(uint32_t ipAddr, uint16_t portNum)
{
	m_raServer = new SGXRemoteAttestationServer(ipAddr, portNum);
}

bool SGXEnclave::IsRAServerLaunched() const
{
	return m_raServer;
}

std::unique_ptr<Connection> SGXEnclave::AcceptRAConnection()
{
	std::unique_ptr<Connection> connection(m_raServer->AcceptRAConnection());
	SGXRemoteAttestationSession RASession(connection, RemoteAttestationSession::Mode::Server);
	bool res = RASession.ProcessServerSideRA(*this);

	return res ? RASession.ReleaseConnection() : nullptr;
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
