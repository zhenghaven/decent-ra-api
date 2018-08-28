#pragma once

#include <string>

namespace Json
{
	class Value;
}

class Messages
{
public:
	static constexpr char sk_LabelRoot[]     = "SmartServerMsg";
	static constexpr char sk_LabelSender[]   = "Sender";
	static constexpr char sk_LabelCategory[] = "Cat";

	static std::string ParseSenderID(const Json::Value& msg);
	static std::string ParseCat(const Json::Value& msg);

public:
	Messages() = delete;
	Messages(const std::string& senderID);
	Messages(const Json::Value& msg, const char* expectedCat);

	virtual ~Messages() {}

	virtual std::string GetMessageCategoryStr() const = 0;

	virtual const std::string& GetSenderID() const;

	virtual std::string ToJsonString() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const;

private:
	const std::string m_senderID;
	//const std::string m_cat;
};