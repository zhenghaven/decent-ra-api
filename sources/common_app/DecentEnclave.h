#pragma once

#include "DecentralizedEnclave.h"

#include <string>
#include <memory>

class Connection;

class DecentEnclave : virtual public DecentralizedEnclave
{
public:
	virtual std::string GetDecentSelfRAReport() const = 0;
	virtual bool ProcessDecentSelfRAReport(const std::string& inReport) = 0;
	virtual bool ProcessDecentTrustedMsg(const std::string& nodeID, const std::unique_ptr<Connection>& connection, const std::string& jsonMsg) = 0;

protected:
	virtual std::string GenerateDecentSelfRAReport() = 0;
};
