#pragma once

#include <string>

#include "Networking/ConnectionHandler.h"

class Connection;
class ClientRASession;
class LocalAttestationSession;
namespace Json
{
	class Value;
}

//TODO: Replace these SGX component with general components.
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;

class EnclaveBase : virtual public ConnectionHandler
{
public:
	virtual ~EnclaveBase() {}

	virtual const char* GetPlatformType() const = 0;

	virtual void GetRAClientSignPubKey(sgx_ec256_public_t& outKey) const = 0;
	virtual const std::string GetRAClientSignPubKey() const = 0;

	virtual ClientRASession* GetRAClientSession(Connection& connection) = 0;
	//Return false only when Connectino is empty.
	virtual bool SendLARequest(Connection& connection) = 0;
	virtual LocalAttestationSession* GetLAInitiatorSession(Connection& connection) = 0;
	virtual LocalAttestationSession* GetLAInitiatorSession(Connection& connection, const Json::Value& ackMsg) = 0;
	virtual LocalAttestationSession* GetLAResponderSession(Connection& connection, const Json::Value& initMsg) = 0;
};

