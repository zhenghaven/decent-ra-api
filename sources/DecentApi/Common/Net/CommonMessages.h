#pragma once

#include <string>
#include "../Tools/JsonForwardDeclare.h"
#include "../RuntimeException.h"

namespace Decent
{
	namespace Net
	{
		class CommonJsonMsgException : public Decent::RuntimeException
		{
		public:
			using RuntimeException::RuntimeException;

		};

		class MessageParsingException : public CommonJsonMsgException
		{
		public:
			MessageParsingException() :
				CommonJsonMsgException("Message parsing error. Invalid message format!")
			{}
		};

		class CommonJsonMsg
		{
		public: //static members:

			/**
			 * \brief	Get a specific JSON value with the specified key.
			 * 			This function is mainly used by the parse function defined below.
			 * 			Known exceptions: MessageParsingException.
			 *
			 * \param	json 	The JSON.
			 * \param	key		The key of the needed value.
			 *
			 * \return	The reference to the JSON value.
			 */
			static const Tools::JsonValue& GetMember(const Tools::JsonValue & json, const char* key);

			/**
			 * \brief	Parses the given JSON value.
			 *
			 * \tparam	T	Generic type parameter. Currently only support bool, int, double, std::string.
			 * \param	json	The JSON object, which is just a single value.
			 *
			 * \return	A T type value.
			 */
			template<typename T>
			static T ParseValue(const Tools::JsonValue & json);

			/**
			 * \brief	Pick the JSON value with the specified key from a JSON object, and parse that value to a c++ value type.
			 *
			 * \tparam	T	Generic type parameter. Currently only support bool, int, double, std::string.
			 * \param	json 	The JSON object, which is a object type.
			 * \param	key		The key of the needed value.
			 *
			 * \return	A T type value.
			 */
			template<typename T>
			static T ParseValue(const Tools::JsonValue & json, const char* key)
			{
				return ParseValue<T>(GetMember(json, key));
			}

			/**
			 * \brief	Parse a sub message inside of a message. For example, message B could be stored inside of a message A.
			 *
			 * \tparam	T	Generic type parameter. It must be a message class that has a constructor accepting JSON object.
			 * \param	json	The JSON object.
			 * \param	key 	The key that used to retrieve the sub json object.
			 *
			 * \return	A T type value.
			 */
			template<typename T>
			static inline T ParseSubMessage(const Tools::JsonValue & json, const char* key)
			{
				return T(GetMember(json, key));
			}

		public:

			/**
			 * \brief	Converts this message to a JSON object
			 *
			 * \param [in,out]	doc	The JSON document.
			 *
			 * \return	JSON value reference to the generated JSON object.
			 */
			virtual Tools::JsonValue& ToJson(Tools::JsonDoc& doc) const = 0;

			/**
			 * \brief	Convert this message into a JSON format string representation
			 *
			 * \return	A std::string that represents this message.
			 */
			virtual std::string ToString() const;

			/**
			 * \brief	Converts this message into a JSON format string with all indentations and new lines.
			 *
			 * \return	A std::string that represents this message.
			 */
			virtual std::string ToStyledString() const;

		};

		template<>
		bool CommonJsonMsg::ParseValue<bool>(const Tools::JsonValue & json);
		template<>
		int CommonJsonMsg::ParseValue<int>(const Tools::JsonValue & json);
		template<>
		double CommonJsonMsg::ParseValue<double>(const Tools::JsonValue & json);
		template<>
		std::string CommonJsonMsg::ParseValue<std::string>(const Tools::JsonValue & json);
	}
}
