#pragma once

#include <memory>
#include <string>
#include "CommSession.h"

class Connection;
class EnclaveBase;

class LocalAttestationSession : public CommSession
{

public:
	LocalAttestationSession() = delete;

	LocalAttestationSession(std::unique_ptr<Connection>& connection, EnclaveBase& enclaveBase);

	virtual ~LocalAttestationSession();

	virtual bool PerformInitiatorSideLA() = 0;
	virtual bool PerformResponderSideLA() = 0;

	virtual std::string GetSenderID() const;

protected:
	EnclaveBase & m_enclaveBase;
	const std::string k_raSenderID;
};
