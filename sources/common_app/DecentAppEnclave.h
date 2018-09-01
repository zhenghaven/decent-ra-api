#pragma once

#include "DecentralizedEnclave.h"

#include <string>
#include <memory>

class Connection;

class DecentAppEnclave : virtual public DecentralizedEnclave
{
public:
	virtual bool SendReportDataToServer(const std::string& decentId, const std::unique_ptr<Connection>& connection) = 0;

	virtual bool ProcessAppReportSignMsg(const std::string& trustedMsg, std::string& outReport, std::string& outSign) = 0;
};
