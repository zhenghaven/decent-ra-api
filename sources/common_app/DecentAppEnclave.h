#pragma once

#include <string>
#include <memory>

class Connection;

class DecentAppEnclave
{
public:
	virtual bool GetX509FromServer(const std::string& decentId, Connection& connection) = 0;

	virtual const std::string& GetAppCert() const = 0;
};
