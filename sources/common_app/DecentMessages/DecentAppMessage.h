#pragma once

#include "../Messages.h"

class DecentAppMessage : public Messages
{
public:
	static constexpr char const sk_LabelRoot[] = "DecentApp";
	static constexpr char const sk_LabelType[] = "Type";

	static constexpr char const sk_ValueCat[] = "DecentApp"; // = sk_LabelRoot;

	static std::string ParseType(const Json::Value& MsgRootContent);

public:
	DecentAppMessage() = delete;
	DecentAppMessage(const std::string& senderID) :
		Messages(senderID)
	{}

	explicit DecentAppMessage(const Json::Value& msg, const char* expectedType);
	virtual ~DecentAppMessage() {}

	virtual std::string GetMessageCategoryStr() const override { return sk_ValueCat; }
	virtual std::string GetMessageTypeStr() const = 0;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

};

class DecentAppErrMsg : public DecentAppMessage, public ErrorMessage
{
public:
	DecentAppErrMsg() = delete;
	DecentAppErrMsg(const std::string& senderID, const std::string& errStr) :
		DecentAppMessage(senderID),
		ErrorMessage(errStr)
	{}

	explicit DecentAppErrMsg(const Json::Value& msg);
	virtual ~DecentAppErrMsg() {}

	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
};

class DecentAppHandshake : public DecentAppMessage
{
public:
	static constexpr char const sk_ValueType[] = "AppHandshake";

public:
	DecentAppHandshake() = delete;
	explicit DecentAppHandshake(const std::string& senderID);
	explicit DecentAppHandshake(const Json::Value& msg);
	virtual ~DecentAppHandshake();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
};

class DecentAppHandshakeAck : public DecentAppMessage
{
public:
	static constexpr char const sk_LabelSelfReport[] = "SelfReport";

	static constexpr char const sk_ValueType[] = "AppHandshakeAck";

	static std::string ParseSelfRAReport(const Json::Value& DecentRoot);

public:
	DecentAppHandshakeAck() = delete;
	explicit DecentAppHandshakeAck(const std::string& senderID, const std::string& selfRAReport);
	explicit DecentAppHandshakeAck(const Json::Value& msg);
	virtual ~DecentAppHandshakeAck();

	virtual std::string GetMessageTypeStr() const override;

	virtual const std::string& GetSelfRAReport() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_selfRAReport;
};
