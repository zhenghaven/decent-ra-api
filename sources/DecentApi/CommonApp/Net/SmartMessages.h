#pragma once

#include <string>

namespace Json
{
	class Value;
}

namespace Decent
{
	namespace Net
	{
		class SmartMessages
		{
		public:
			static constexpr char const sk_LabelRoot[] = "SmartServerMsg";
			static constexpr char const sk_LabelSender[] = "Sender";
			static constexpr char const sk_LabelCategory[] = "Cat";
			static constexpr char const sk_LabelChild[] = "Child";

			static std::string ParseSenderID(const Json::Value& msg);
			static std::string ParseCat(const Json::Value& msg);

		public:
			SmartMessages();
			SmartMessages(const std::string& senderId);
			SmartMessages(const Json::Value& msg, const char* expectedCat);

			virtual ~SmartMessages() {}

			virtual std::string GetMessageCategoryStr() const = 0;

			const std::string& GetSenderID() const { return m_senderID; }

			virtual std::string ToJsonString() const;

		protected:
			virtual Json::Value& GetJsonMsg(Json::Value& outJson) const;

		private:
			const std::string m_senderID;
		};

		class ErrorMessage
		{
		public:
			static constexpr char const sk_LabelErrMsg[] = "ErrorMsg";

			static constexpr char const sk_ValueType[] = "Error";

			static std::string ParseErrorMsg(const Json::Value& typeRoot);

		public:
			ErrorMessage() = delete;

			explicit ErrorMessage(const std::string& errStr) :
				m_errStr(errStr)
			{}

			explicit ErrorMessage(const Json::Value& typeRoot) :
				m_errStr(ParseErrorMsg(typeRoot))
			{}

			virtual ~ErrorMessage() {}

			const std::string& GetErrorStr() const { return m_errStr; }

		private:
			const std::string m_errStr;
		};

	}
}
