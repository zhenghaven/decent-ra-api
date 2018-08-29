#pragma once

#include <memory>

class Connection;

class Server
{
public:
	virtual ~Server() {}

	///Warning: Blocking method! This method will be blocked until a connection is accepted.
	virtual std::unique_ptr<Connection> AcceptConnection() = 0;
};
