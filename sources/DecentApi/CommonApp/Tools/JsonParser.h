#pragma once

#include <string>

#include "../../Common/Tools/JsonForwardDeclare.h"
#include "../../Common/Exceptions.h"

namespace Decent
{
	namespace Tools
	{
		class JsonParseError : public RuntimeException
		{
		public:
			JsonParseError() :
				RuntimeException("Configuration File Parse Error!")
			{}
		};

		const JsonValue& JsonGetValue(const JsonValue& json, const std::string& label);

		std::string JsonGetString(const JsonValue& json);

		std::string JsonGetStringFromObject(const JsonValue& json, const std::string& label);

		uint32_t JsonGetInt(const JsonValue& json);

		uint32_t JsonGetIntFromObject(const JsonValue& json, const std::string& label);

		bool JsonGetBool(const JsonValue& json);

		bool JsonGetBoolFromObject(const JsonValue& json, const std::string& label);
	}
}
