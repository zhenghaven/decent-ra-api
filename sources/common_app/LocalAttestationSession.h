#pragma once

#include <memory>
#include <string>
#include "CommSession.h"

class Connection;
class EnclaveBase;

template<typename T>
class LocalAttestationSession : public CommSession
{
	static_assert(std::is_base_of<EnclaveBase, T>::value, "Class type must be a child class of EnclaveBase.");
public:
	LocalAttestationSession() = delete;

	LocalAttestationSession(std::unique_ptr<Connection>& connection, T& hwEnclave) :
		m_hwEnclave(hwEnclave),
		k_raSenderID(hwEnclave.GetRAClientSignPubKey())
	{
		m_connection.swap(connection);
	}

	virtual ~LocalAttestationSession() {}

	virtual bool PerformInitiatorSideLA() = 0;
	virtual bool PerformResponderSideLA() = 0;

	virtual std::string GetSenderID() const { return k_raSenderID; }

protected:
	T& m_hwEnclave;
	const std::string k_raSenderID;
};
