#pragma once

#include <exception>
#include <string>

namespace Decent
{
	class RuntimeException : public std::exception
	{
	public:
		explicit RuntimeException(const std::string& what_arg) :
			std::exception(what_arg.c_str())
		{}

		explicit RuntimeException(const char* what_arg) :
			std::exception(what_arg)
		{}

	private:

	};
}
