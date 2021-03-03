#pragma once

#include <stdexcept>
#include <string>

namespace Decent
{
	class RuntimeException : public std::runtime_error
	{
	public:
		explicit RuntimeException(const std::string& what_arg) :
			std::runtime_error(what_arg)
		{}

		explicit RuntimeException(const char* what_arg) :
			std::runtime_error(what_arg)
		{}
	};

	class InvalidArgumentException : public std::invalid_argument
	{
	public:
		explicit InvalidArgumentException(const std::string& what_arg) :
			std::invalid_argument(what_arg)
		{}

		explicit InvalidArgumentException(const char* what_arg) :
			std::invalid_argument(what_arg)
		{}
	};
}
