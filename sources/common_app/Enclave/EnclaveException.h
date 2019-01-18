#pragma once

#include <exception>

namespace Decent
{
	namespace Base
	{
		class EnclaveException : public std::exception
		{
		public:
			EnclaveException() {}

			virtual ~EnclaveException() {}

			virtual const char* what() const throw()
			{
				return "General Enclave Exception.";
			}
		};
	}
}
