#pragma once

#include <exception>

class EnclaveException : public std::exception
{
public:
	EnclaveException();
	virtual ~EnclaveException();

	virtual const char* what() const throw()
	{
		return "General Enclave Exception.";
	}
private:

};
