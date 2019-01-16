#pragma once

#include "../SmartMessages.h"

namespace Decent
{
	namespace Message
	{
		class LoadWhiteList : public SmartMessages
		{
		public:
			static constexpr char const sk_LabelRoot[] = "DecentLoadWhiteList";
			static constexpr char const sk_ValueCat[] = "DecentLoadWhiteList";

			static constexpr char const sk_LabelKey[] = "Key";
			static constexpr char const sk_LabelWhiteList[] = "WhiteList";

			static std::string ParseKey(const Json::Value& DecentRoot);
			static std::string ParseWhiteList(const Json::Value& DecentRoot);

		public:
			LoadWhiteList() = delete;
			LoadWhiteList(const std::string& key, const std::string& whiteList) :
				SmartMessages(""),
				m_key(key),
				m_whiteList(whiteList)
			{}

			explicit LoadWhiteList(const Json::Value& msg);

			virtual ~LoadWhiteList() {}

			virtual std::string GetMessageCategoryStr() const override { return sk_ValueCat; }

			virtual const std::string& GetKey() const { return m_key; }
			virtual const std::string& GetWhiteList() const { return m_whiteList; }

		protected:
			virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

		private:
			const std::string m_key;
			const std::string m_whiteList;
		};

		class RequestAppCert : public SmartMessages
		{
		public:
			static constexpr char const sk_LabelRoot[] = "DecentRequestAppCert";
			static constexpr char const sk_ValueCat[] = "DecentRequestAppCert";

			static constexpr char const sk_LabelKey[] = "Key";

			static std::string ParseKey(const Json::Value& DecentRoot);

		public:
			RequestAppCert() = delete;
			RequestAppCert(const std::string& key) :
				SmartMessages(""),
				m_key(key)
			{}

			explicit RequestAppCert(const Json::Value& msg);

			virtual ~RequestAppCert() {}

			virtual std::string GetMessageCategoryStr() const override { return sk_ValueCat; }

			virtual const std::string& GetKey() const { return m_key; }

		protected:
			virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

		private:
			const std::string m_key;
		};
	}
}


