#pragma once

#include <string>
#include <memory>

class Connection;

class DecentAppEnclave
{
public:
	virtual bool ProcessDecentSelfRAReport(std::string& inReport) = 0;

	virtual bool SendReportDataToServer(const std::string& decentId, const std::unique_ptr<Connection>& connection) = 0;

	virtual bool ProcessAppReportSignMsg(const std::string& trustedMsg) = 0;

	virtual const std::string& GetDecentRAReport() const = 0;
	virtual const std::string& GetEnclaveReport() const = 0;
	virtual const std::string& GetEnclaveReportSign() const = 0;
};
