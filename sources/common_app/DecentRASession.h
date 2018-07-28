#pragma once

#include "DecentralizedRASession.h"

#include <string>

class DecentEnclave;
class DecentMessageMsg0;

class DecentRASession : public DecentralizedRASession
{
public:
	DecentRASession() = delete;
	DecentRASession(std::unique_ptr<Connection>& connection, EnclaveBase& hardwareEnclave, ServiceProviderBase& sp, DecentEnclave& enclave);

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
	virtual bool ProcessClientSideRA() override;

	/**
	 * \brief	Process the server side Remote Attestation.
	 * 			If the role of the DecentEnclave is application server, then the ProcessServerMessage0 will be called.
	 * 			If the role is root server, then this method will process the Remote Attestation request.
	 *
	 * \param [in,out]	enclave	The enclave object. The enclave object here must be a instance of Decent enclave. 
	 *
	 * \return	True if it succeeds, false if it fails.
	 */
	virtual bool ProcessServerSideRA() override;

	/**
	 * \brief	Process the client side Decent Protocol Message 0.
	 *
	 * \param [in,out]	enclave	The enclave object.
	 *
	 * \return	True if it succeeds, false if it fails.
	 */
	virtual bool ProcessClientMessage0();

	/**
	 * \brief	Process the server side Decent Protocol Message 0.
	 *
	 * \param [in,out]	enclave	The enclave object.
	 *
	 * \return	True if it succeeds, false if it fails.
	 */
	virtual bool ProcessServerMessage0();

protected:
	/**
	 * \brief	Process the client side key request. This method can be called by a root or application server.
	 *
	 * \param [in,out]	enclave	The enclave object.
	 *
	 * \return	True if it succeeds, false if it fails.
	 */
	virtual bool ProcessClientSideKeyRequest();

	/**
	 * \brief	Process the server side key request. This method should only called by a root server.
	 *
	 * \param [in,out] enclave The enclave object.
	 *
	 * \return True if it succeeds, false if it fails.
	 */
	virtual bool ProcessServerSideKeyRequest();

private:
	DecentEnclave& m_decentEnclave;

	DecentMessageMsg0* ConstructMessage0();
};
