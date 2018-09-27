#pragma once

#include <string>
#include <memory>

class Connection;

class DecentAppEnclave
{
public:
	virtual bool ProcessDecentSelfRAReport(std::string& inReport) = 0;

	virtual bool SendCertReqToServer(const std::string& decentId, Connection& connection) = 0;

	virtual bool ProcessAppReportSignMsg(const std::string& trustedMsg) = 0;

	virtual const std::string& GetDecentRAReport() const = 0;
	virtual const std::string& GetAppCert() const = 0;
};
