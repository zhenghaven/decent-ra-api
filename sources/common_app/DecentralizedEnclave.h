#pragma once

#include <memory>

class EnclaveBase;
class Connection;

class DecentralizedEnclave
{
public:
	DecentralizedEnclave() = delete;
	DecentralizedEnclave(std::shared_ptr<EnclaveBase> enclaveHardware);
	virtual ~DecentralizedEnclave();

	virtual std::unique_ptr<Connection> AcceptRAConnection() = 0;
	virtual std::unique_ptr<Connection> RequestRA(uint32_t ipAddr, uint16_t portNum) = 0;

	virtual std::shared_ptr<EnclaveBase> GetEnclaveHardware();

	virtual const std::shared_ptr<const EnclaveBase>& GetEnclaveHardware() const;

protected:
	std::shared_ptr<EnclaveBase> m_enclaveHardware;

private:

};
