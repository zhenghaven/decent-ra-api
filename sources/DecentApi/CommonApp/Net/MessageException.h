#pragma once

#include "../../Common/RuntimeException.h"

namespace Decent
{
	namespace Net
	{
		class MessageException : public Decent::RuntimeException
		{
		public:
			explicit MessageException(const std::string& what_arg) :
				RuntimeException(what_arg.c_str())
			{}

			explicit MessageException(const char* what_arg) :
				RuntimeException(what_arg)
			{}

		};

		class ReceivedErrorMessage : public MessageException
		{
		public:
			explicit ReceivedErrorMessage(const std::string& msgContent) :
				MessageException("Peer's Error Message: " + msgContent + ". ")
			{}

			explicit ReceivedErrorMessage(const char* msgContent) :
				MessageException(std::string(msgContent))
			{}

		};

		class MessageParseException : public MessageException
		{
		public:
			MessageParseException() :
				MessageException("Smart Message Parse Error. Invalid Format!")
			{}

		};
	}
}
