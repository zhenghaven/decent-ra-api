#pragma once

#include <string>
#include <memory>
#include "CommSession.h"

class DecentEnclave;
class Connection;
class EnclaveServiceProviderBase;
class DecentRAHandshake;
class DecentRAHandshakeAck;
namespace Json
{
	class Value;
}

class DecentRASession : public CommSession
{
public:
	static void SendHandshakeMessage(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& enclave);
	static bool SmartMsgEntryPoint(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentEnclave& enclave, const Json::Value& jsonMsg);

public:
	DecentRASession() = delete;
	DecentRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentEnclave& enclave);
	DecentRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentEnclave& enclave, const DecentRAHandshake& hsMsg);
	DecentRASession(std::unique_ptr<Connection>& connection, EnclaveServiceProviderBase& hwEnclave, DecentEnclave& enclave, const DecentRAHandshakeAck& ackMsg);

	virtual ~DecentRASession();

	/**
	 * \brief	Process the client side Remote Attestation.
	 * 			It's used to request Remote Attestation to a root server. ProcessClientSideKeyRequest will be called after the RA is done.
	 * 			If the role of the DecentEnclave is application server, then the signature for the key will be requested.
	 * 			If the role is root server, then the protocol key will be requested. 
	 *
	 * \param [in,out]	enclave	The enclave object. The enclave object here must be a instance of Decent enclave. 
	 *
	 * \return	True if it succeeds, false if it fails.
	 */
	virtual bool ProcessClientSideRA();

	/**
	 * \brief	Process the server side Remote Attestation.
	 * 			If the role of the DecentEnclave is application server, then the ProcessServerMessage0 will be called.
	 * 			If the role is root server, then this method will process the Remote Attestation request.
	 *
	 * \param [in,out]	enclave	The enclave object. The enclave object here must be a instance of Decent enclave. 
	 *
	 * \return	True if it succeeds, false if it fails.
	 */
	virtual bool ProcessServerSideRA();

private:
	const std::string k_senderID;
	const std::string k_remoteSideID;
	EnclaveServiceProviderBase& m_hwEnclave;
	DecentEnclave& m_decentEnclave;
	const bool k_isServerSide;
};
