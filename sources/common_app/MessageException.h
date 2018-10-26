#pragma once

#include <exception>

class MessageException : public std::exception
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

class ReceivedErrorMessageException : public MessageException
{
public:
	ReceivedErrorMessageException()
	{}
	~ReceivedErrorMessageException()
	{}

	virtual const char* what() const throw()
	{
		return "Received a error message from the remote side.";
	}
private:

};

class MessageInvalidException : public MessageException
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

class MessageParseException : public MessageInvalidException
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
