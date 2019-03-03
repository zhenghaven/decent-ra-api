#pragma once

#include <stdexcept>
#include <string>

namespace Decent
{
	class RuntimeException : public std::runtime_error
	{
	public:
		explicit RuntimeException(const std::string& what_arg) :
			std::runtime_error(what_arg.c_str())
		{}

		explicit RuntimeException(const char* what_arg) :
			std::runtime_error(what_arg)
		{}

	private:

	};
}
