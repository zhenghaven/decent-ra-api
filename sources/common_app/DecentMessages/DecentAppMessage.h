#pragma once

#include "../Messages.h"

//class DecentAppMessage : public Messages
//{
//public:
//	static constexpr char const sk_LabelRoot[] = "DecentApp";
//	static constexpr char const sk_LabelType[] = "Type";
//
//	static constexpr char const sk_ValueCat[] = "DecentApp"; // = sk_LabelRoot;
//
//	static std::string ParseType(const Json::Value& MsgRootContent);
//
//public:
//	DecentAppMessage() = delete;
//	DecentAppMessage(const std::string& senderID) :
//		Messages(senderID)
//	{}
//
//	explicit DecentAppMessage(const Json::Value& msg, const char* expectedType);
//	virtual ~DecentAppMessage() {}
//
//	virtual std::string GetMessageCategoryStr() const override { return sk_ValueCat; }
//	virtual std::string GetMessageTypeStr() const = 0;
//
//protected:
//	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
//
//};
//
//class DecentAppErrMsg : public DecentAppMessage, public ErrorMessage
//{
//public:
//	DecentAppErrMsg() = delete;
//	DecentAppErrMsg(const std::string& senderID, const std::string& errStr) :
//		DecentAppMessage(senderID),
//		ErrorMessage(errStr)
//	{}
//
//	explicit DecentAppErrMsg(const Json::Value& msg);
//	virtual ~DecentAppErrMsg() {}
//
//	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }
//
//protected:
//	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
//};

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

//class DecentAppHandshake : public DecentAppMessage
//{
//public:
//	static constexpr char const sk_ValueType[] = "AppHandshake";
//
//public:
//	DecentAppHandshake() = delete;
//	DecentAppHandshake(const std::string& senderID) :
//		DecentAppMessage(senderID)
//	{}
//
//	explicit DecentAppHandshake(const Json::Value& msg) :
//		DecentAppMessage(msg, sk_ValueType)
//	{}
//
//	virtual ~DecentAppHandshake() {}
//
//	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }
//
//protected:
//	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override
//	{
//		return DecentAppMessage::GetJsonMsg(outJson);
//	}
//};
//
//class DecentAppHandshakeAck : public DecentAppMessage
//{
//public:
//	static constexpr char const sk_LabelSelfReport[] = "SelfReport";
//
//	static constexpr char const sk_ValueType[] = "AppHandshakeAck";
//
//	static std::string ParseSelfRAReport(const Json::Value& DecentRoot);
//
//public:
//	DecentAppHandshakeAck() = delete;
//	DecentAppHandshakeAck(const std::string& senderID, const std::string& selfRAReport) :
//		DecentAppMessage(senderID),
//		m_selfRAReport(selfRAReport)
//	{}
//
//	explicit DecentAppHandshakeAck(const Json::Value& msg);
//	virtual ~DecentAppHandshakeAck() {}
//
//	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }
//
//	virtual const std::string& GetSelfRAReport() const { return m_selfRAReport; }
//
//protected:
//	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
//
//private:
//	const std::string m_selfRAReport;
//};
