#pragma once

#include <exception>

class MessageException
{
public:
	MessageException()
	{}
	virtual ~MessageException()
	{}

	virtual const char* what() const throw()
	{
		return "General Smart Server Message Exception.";
	}
private:

};

class MessageInvalidException
{
public:
	MessageInvalidException()
	{}
	virtual ~MessageInvalidException()
	{}

	virtual const char* what() const throw()
	{
		return "Message contains invalid contents that may cause process error!";
	}
private:

};

class MessageParseException
{
public:
	MessageParseException()
	{}
	virtual ~MessageParseException()
	{}

	virtual const char* what() const throw()
	{
		return "Smart Server Message Parse Error. Invalid message format!";
	}
private:

};
