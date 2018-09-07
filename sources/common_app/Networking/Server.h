#pragma once

#include <memory>

class Connection;

class Server
{
public:
	virtual ~Server() noexcept {}

	///Warning: Blocking method! This method will be blocked until a connection is accepted.
	virtual std::unique_ptr<Connection> AcceptConnection() = 0;

	virtual bool IsTerminated() noexcept = 0;

	virtual void Terminate() noexcept = 0;
};
