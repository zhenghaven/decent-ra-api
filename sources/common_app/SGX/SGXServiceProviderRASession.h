#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#pragma once

#include "../ServiceProviderRASession.h"

#include <string>

class SGXServiceProviderBase;
class IASConnector;
class SGXRAMessage0Send;
namespace Json
{
	class Value;
}

class SGXServiceProviderRASession : public ServiceProviderRASession
{
public:
	static bool SmartMsgEntryPoint(Connection& connection, SGXServiceProviderBase& serviceProviderBase, const IASConnector& ias, const Json::Value& jsonMsg);

public:
	SGXServiceProviderRASession() = delete;
	SGXServiceProviderRASession(Connection& connection, SGXServiceProviderBase& serviceProviderBase, const IASConnector& ias);
	SGXServiceProviderRASession(Connection& connection, SGXServiceProviderBase& serviceProviderBase, const IASConnector& ias, const SGXRAMessage0Send& msg0s);
	virtual ~SGXServiceProviderRASession();

	virtual bool ProcessServerSideRA() override;

	virtual const std::string GetSenderID() const override { return k_senderId; }

	virtual const std::string GetRemoteReceiverID() const override { return k_remoteSideId; }

protected:
	const std::string k_senderId;
	const std::string k_remoteSideId;
	SGXServiceProviderBase& m_sgxSP;
	const IASConnector& m_ias;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
