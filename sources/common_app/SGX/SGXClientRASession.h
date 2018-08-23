#pragma once

#include "../ClientRASession.h"

#include <memory>

#include <sgx_tcrypto.h>

class IASConnector;
class SGXEnclave;
class SGXRAMessage0Resp;
namespace Json
{
	class Value;
}

class SGXClientRASession : public ClientRASession
{
public:
	static void SendHandshakeMessage(std::unique_ptr<Connection>& connection, SGXEnclave& enclave);
	static bool SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, SGXEnclave& enclave, const Json::Value& msg);

public:
	SGXClientRASession() = delete;
	//Caution: blocking constructor:
	SGXClientRASession(std::unique_ptr<Connection>& connection, SGXEnclave& enclave);
	SGXClientRASession(std::unique_ptr<Connection>& connection, SGXEnclave& enclave, const SGXRAMessage0Resp& msg0r);

	virtual ~SGXClientRASession();

	virtual bool ProcessClientSideRA() override;

protected:
	SGXEnclave& m_sgxEnclave;
	const std::string k_remoteSideID;
	const sgx_ec256_public_t k_remoteSideSignKey;
};
