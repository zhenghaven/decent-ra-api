#include "DecentServer.h"

#include "../Crypto.h"
#include "../RaReport.h"
#include "../States.h"

#include "HardCoded.h"

using namespace Decent;
using namespace Decent::Ra;
using namespace Decent::Ra::WhiteList;

DecentServer::DecentServer()
{
}

DecentServer::~DecentServer()
{
}

bool DecentServer::AddTrustedNode(const ServerX509 & cert)
{
	std::string pubKeyPem = cert.GetEcPublicKey().ToPubPemString();
	
	if (IsNodeTrusted(pubKeyPem) && VerifyCertAfterward(cert))
	{
		return true;
	}

	std::string serverHash;
	if (!States::Get().GetHardCodedWhiteList().GetHash(HardCoded::sk_decentServerLabel, serverHash))
	{
		return false;
	}

	TimeStamp timestamp;
	bool verifyRes = RaReport::ProcessSelfRaReport(cert.GetPlatformType(), pubKeyPem,
		cert.GetSelfRaReport(), serverHash, timestamp);

	//TODO: enable this once the DecentServer is released.
	//if (!verifyRes && VerifyCertFirstTime(cert))
	//{
	//	return false;
	//}

	{
		std::unique_lock<std::mutex> nodeMapLock(m_acceptedNodesMutex);
		m_acceptedNodes[pubKeyPem] = timestamp;
	}

	return true;
}

bool DecentServer::IsNodeTrusted(const std::string & key) const
{
	std::unique_lock<std::mutex> nodeMapLock(m_acceptedNodesMutex);
	return m_acceptedNodes.find(key) != m_acceptedNodes.cend();
}

bool DecentServer::GetAcceptedTimestamp(const std::string & key, TimeStamp& outTime) const
{
	std::unique_lock<std::mutex> nodeMapLock(m_acceptedNodesMutex);
	auto it = m_acceptedNodes.find(key);
	bool isFound = it != m_acceptedNodes.cend();
	if (isFound)
	{
		outTime = it->second;
	}
	return isFound;
}

bool DecentServer::VerifyCertFirstTime(const ServerX509 & cert) const
{
	return true;
}

bool DecentServer::VerifyCertAfterward(const ServerX509 & cert) const
{
	return true;
}
