#include "DecentServer.h"

#include "../../Common.h"

#include "../../MbedTls/AsymKeyBase.h"

#include "../ServerX509Cert.h"
#include "../RaReport.h"
#include "../States.h"

#include "LoadedList.h"

using namespace Decent::MbedTlsObj;
using namespace Decent::Ra;
using namespace Decent::Ra::WhiteList;

DecentServer::DecentServer()
{
}

DecentServer::~DecentServer()
{
}

bool DecentServer::AddTrustedNode(States& decentState, const ServerX509Cert & cert)
{
	std::string pubKeyPem = AsymKeyBase(const_cast<ServerX509Cert&>(cert).GetCurrPublicKey()).GetPublicPem();
	
	if (IsNodeTrusted(pubKeyPem))
	{
		return VerifyCertAfterward(decentState, cert);
	}
	else
	{
		report_timestamp_t timestamp;
		std::string serverHash;
		return VerifyCertFirstTime(decentState, cert, pubKeyPem, serverHash, timestamp) && 
			AddToWhiteListMap(decentState, cert, pubKeyPem, serverHash, timestamp);
	}
}

bool DecentServer::IsNodeTrusted(const std::string & key) const
{
	std::unique_lock<std::mutex> nodeMapLock(m_acceptedNodesMutex);
	return m_acceptedNodes.find(key) != m_acceptedNodes.cend();
}

bool DecentServer::GetAcceptedTimestamp(const std::string & key, report_timestamp_t& outTime) const
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

bool DecentServer::VerifyCertFirstTime(States& decentState, const ServerX509Cert & cert, const std::string& pubKeyPem, std::string& serverHash, report_timestamp_t& timestamp)
{
	bool verifyRes = RaReport::ProcessSelfRaReport(cert.GetPlatformType(), pubKeyPem,
		cert.GetSelfRaReport(), serverHash, timestamp);

#ifndef DEBUG
	return verifyRes &&
		decentState.GetLoadedWhiteList().CheckHashAndName(serverHash, sk_nameDecentServer);
#else
	LOGW("%s() passed DecentServer with hash, %s,  without checking!", __FUNCTION__, serverHash.c_str());
	return true;
#endif // !DEBUG
}

bool DecentServer::VerifyCertAfterward(States& decentState, const ServerX509Cert & cert)
{
	return true;
}

bool DecentServer::AddToWhiteListMap(States & decentState, const ServerX509Cert & cert, const std::string & pubKeyPem, const std::string & serverHash, const report_timestamp_t & timestamp)
{
	std::unique_lock<std::mutex> nodeMapLock(m_acceptedNodesMutex);
	m_acceptedNodes[pubKeyPem] = timestamp;
	return true;
}
