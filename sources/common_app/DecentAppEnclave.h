#pragma once

#include <string>
#include <memory>

class Connection;

class DecentAppEnclave
{
public:
	//virtual bool ProcessDecentSelfRAReport(std::string& inReport) = 0;
	//virtual bool ProcessDecentSelfRAReport(const std::string& inReport) = 0;

	virtual bool GetX509FromServer(const std::string& decentId, Connection& connection) = 0;

	virtual const std::string& GetDecentRAReport() const = 0;
	virtual const std::string& GetAppCert() const = 0;
};
