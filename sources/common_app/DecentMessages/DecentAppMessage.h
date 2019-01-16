#pragma once

#include "../Messages.h"

class DecentLoadWhiteList : public Messages
{
public:
	static constexpr char const sk_LabelRoot[] = "DecentLoadWhiteList";
	static constexpr char const sk_ValueCat[]  = "DecentLoadWhiteList";

	static constexpr char const sk_LabelKey[] = "Key";
	static constexpr char const sk_LabelWhiteList[] = "WhiteList";

	static std::string ParseKey(const Json::Value& DecentRoot);
	static std::string ParseWhiteList(const Json::Value& DecentRoot);

public:
	DecentLoadWhiteList() = delete;
	DecentLoadWhiteList(const std::string& key, const std::string& whiteList) :
		Messages(""),
		m_key(key),
		m_whiteList(whiteList)
	{}

	explicit DecentLoadWhiteList(const Json::Value& msg);

	virtual ~DecentLoadWhiteList() {}

	virtual std::string GetMessageCategoryStr() const override { return sk_ValueCat; }

	virtual const std::string& GetKey() const { return m_key; }
	virtual const std::string& GetWhiteList() const { return m_whiteList; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_key;
	const std::string m_whiteList;
};

class DecentRequestAppCert : public Messages
{
public:
	static constexpr char const sk_LabelRoot[] = "DecentRequestAppCert";
	static constexpr char const sk_ValueCat[] = "DecentRequestAppCert";

	static constexpr char const sk_LabelKey[] = "Key";

	static std::string ParseKey(const Json::Value& DecentRoot);

public:
	DecentRequestAppCert() = delete;
	DecentRequestAppCert(const std::string& key) :
		Messages(""),
		m_key(key)
	{}

	explicit DecentRequestAppCert(const Json::Value& msg);

	virtual ~DecentRequestAppCert() {}

	virtual std::string GetMessageCategoryStr() const override { return sk_ValueCat; }

	virtual const std::string& GetKey() const { return m_key; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_key;
};
