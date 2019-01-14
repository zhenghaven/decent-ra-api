#include "DecentServer.h"

#include "../DecentCrypto.h"
#include "../DecentRAReport.h"

#include "HardCoded.h"

using namespace Decent::WhiteList;

Decent::WhiteList::DecentServer::~DecentServer()
{
}

bool Decent::WhiteList::DecentServer::AddTrustedNode(const Decent::ServerX509 & cert)
{
	std::string pubKeyPem = cert.GetEcPublicKey().ToPubPemString();
	
	if (IsNodeTrusted(pubKeyPem) && VerifyCertAfterward(cert))
	{
		return true;
	}

	auto serverHashIt = HardCoded::Get().find(HardCoded::sk_decentServerLabel);
	if (serverHashIt == HardCoded::Get().cend())
	{
		return false;
	}

	TimeStamp timestamp;
	const std::string& serverHash = serverHashIt->second;
	bool verifyRes = Decent::RAReport::ProcessSelfRaReport(cert.GetPlatformType(), pubKeyPem,
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

bool Decent::WhiteList::DecentServer::IsNodeTrusted(const std::string & key) const
{
	std::unique_lock<std::mutex> nodeMapLock(m_acceptedNodesMutex);
	return m_acceptedNodes.find(key) != m_acceptedNodes.cend();
}

bool Decent::WhiteList::DecentServer::GetAcceptedTimestamp(const std::string & key, TimeStamp& outTime) const
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

bool Decent::WhiteList::DecentServer::VerifyCertFirstTime(const ServerX509 & cert) const
{
	return true;
}

bool Decent::WhiteList::DecentServer::VerifyCertAfterward(const ServerX509 & cert) const
{
	return true;
}

Decent::WhiteList::DecentServer::DecentServer()
{
}
