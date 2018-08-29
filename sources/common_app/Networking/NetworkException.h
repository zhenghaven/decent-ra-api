#pragma once

#include <exception>

class NetworkException : public std::exception
{
public:
	NetworkException()
	{}
	virtual ~NetworkException()
	{}

	virtual const char* what() const throw()
	{
		return "General Network Exception.";
	}
private:

};

class ServerAddressOccupiedException : public NetworkException
{
public:
	ServerAddressOccupiedException()
	{}
	~ServerAddressOccupiedException()
	{}

	virtual const char* what() const throw()
	{
		return "The address is occupied by other running server!";
	}
private:

};

class ConnectionClosedException : public NetworkException
{
public:
	ConnectionClosedException()
	{}
	~ConnectionClosedException()
	{}

	virtual const char* what() const throw()
	{
		return "The connection is closed!";
	}
private:

};
