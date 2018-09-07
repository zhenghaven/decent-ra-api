#pragma once

#include <string>

class Connection;

class DecentEnclave
{
public:
	virtual std::string GetDecentSelfRAReport() const = 0;
	virtual bool ProcessDecentSelfRAReport(const std::string& inReport) = 0;
	virtual bool DecentBecomeRoot() = 0;
	virtual bool ProcessDecentProtoKeyMsg(const std::string& nodeID, Connection& connection, const std::string& jsonMsg) = 0;
	virtual bool SendProtocolKey(const std::string& nodeID, Connection& connection) = 0;
	virtual bool ProcessAppReportSignReq(const std::string& appId, Connection& connection, const std::string& jsonMsg, const char* appAttach) = 0;

protected:
	virtual std::string GenerateDecentSelfRAReport() = 0;
};
