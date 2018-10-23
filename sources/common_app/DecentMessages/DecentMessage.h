#pragma once

#include "../Messages.h"

class DecentMessage : public Messages
{
public:
	static constexpr char const sk_LabelRoot[] = "Decent";
	static constexpr char const sk_LabelType[] = "Type";

	static constexpr char const sk_ValueCat[] = "Decent"; // = sk_LabelRoot;

	static std::string ParseType(const Json::Value& MsgRootContent);

public:
	DecentMessage() = delete;
	DecentMessage(const std::string& senderID) :
		Messages(senderID)
	{}

	DecentMessage(const Json::Value& msg, const char* expectedType);
	~DecentMessage() {}

	virtual std::string GetMessageCategoryStr() const override { return sk_ValueCat; }
	virtual std::string GetMessageTypeStr() const = 0;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
};

class DecentErrMsg : public DecentMessage, public ErrorMessage
{
public:
	DecentErrMsg() = delete;
	DecentErrMsg(const std::string& senderID, const std::string& errStr) :
		DecentMessage(senderID),
		ErrorMessage(errStr)
	{}

	DecentErrMsg(const Json::Value& msg);
	virtual ~DecentErrMsg() {}

	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
};

class DecentRAHandshake : public DecentMessage
{
public:
	static constexpr char const sk_ValueType[] = "RAHandshake";

public:
	DecentRAHandshake() = delete;
	explicit DecentRAHandshake(const std::string& senderID) :
		DecentMessage(senderID)
	{}

	explicit DecentRAHandshake(const Json::Value& msg) :
		DecentMessage(msg, sk_ValueType)
	{}

	virtual ~DecentRAHandshake() {}

	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override
	{
		return DecentMessage::GetJsonMsg(outJson);
	}
};

class DecentRAHandshakeAck : public DecentMessage
{
public:
	static constexpr char const sk_LabelSelfReport[] = "SelfReport";

	static constexpr char const sk_ValueType[] = "RAHandshakeAck";

	static std::string ParseSelfRAReport(const Json::Value& DecentRoot);

public:
	DecentRAHandshakeAck() = delete;
	explicit DecentRAHandshakeAck(const std::string& senderID, const std::string& selfRAReport) :
		DecentMessage(senderID),
		m_selfRAReport(selfRAReport)
	{}

	explicit DecentRAHandshakeAck(const Json::Value& msg);
	virtual ~DecentRAHandshakeAck() {}

	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }

	virtual const std::string& GetSelfRAReport() const { return m_selfRAReport; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_selfRAReport;
};
