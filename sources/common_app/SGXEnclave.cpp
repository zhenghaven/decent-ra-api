#include "SGXEnclave.h"

#include <sgx_urts.h>

#include <boost/filesystem/operations.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "Common.h"
#include "SGXRemoteAttestationSession.h"

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
	m_RAServerIO(nullptr),
	m_RAServerAcc(nullptr)
{
}

SGXEnclave::SGXEnclave(const std::string enclavePath, const KnownFolderType tokenLocType, const std::string tokenFileName) :
	SGXEnclave(enclavePath, GetKnownFolderPath(tokenLocType).append(tokenFileName))
{
	fs::path tokenFolder = m_tokenPath.parent_path();
	fs::create_directories(tokenFolder);
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

void SGXEnclave::LaunchRemoteAttestationServer(uint32_t ipAddr, short port)
{
	m_RAServerIO = new boost::asio::io_service;
	m_RAServerAcc = new boost::asio::ip::tcp::acceptor(*m_RAServerIO, ip::tcp::endpoint(ip::address_v4(ipAddr), port));
}

bool SGXEnclave::IsRAServerLaunched() const
{
	return (m_RAServerIO && m_RAServerAcc);
}

RemoteAttestationSession* SGXEnclave::AcceptRAConnection()
{
	if (!IsRAServerLaunched())
	{
		return nullptr;
	}
	RemoteAttestationSession* session = new SGXRemoteAttestationSession(*m_RAServerAcc);
	return session;
}

sgx_status_t SGXEnclave::GetLastStatus() const
{
	return m_lastStatus;
}

SGXEnclave::~SGXEnclave()
{
	if (IsLaunched())
	{
		sgx_destroy_enclave(m_eid);
	}
	if (m_RAServerIO)
	{
		delete m_RAServerIO;
	}
	if (m_RAServerAcc)
	{
		delete m_RAServerAcc;
	}
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