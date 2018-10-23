#pragma once

#include "../common_app/Messages.h"

#include <json/json.h>

#include "../common_app/MessageException.h"

class VoteAppMessage : public Messages
{
public:
	static constexpr char const sk_LabelRoot[] = "VoteApp";
	static constexpr char const sk_LabelType[] = "Type";

	static constexpr char const sk_ValueCat[] = "VoteApp"; // = sk_LabelRoot;

	static std::string ParseType(const Json::Value& MsgRootContent)
	{
		if (MsgRootContent.isMember(sk_LabelRoot) && MsgRootContent[sk_LabelRoot].isObject() &&
			MsgRootContent[sk_LabelRoot].isMember(sk_LabelType) && MsgRootContent[sk_LabelRoot][sk_LabelType].isString()
			)
		{
			return MsgRootContent[sk_LabelRoot][sk_LabelType].asString();
		}
		throw MessageParseException();
	}

public:
	VoteAppMessage() = delete;
	VoteAppMessage(const std::string& senderID) :
		Messages(senderID)
	{}

	VoteAppMessage(const Json::Value& msg, const char* expectedType) :
		Messages(msg, sk_ValueCat)
	{
		if (expectedType && ParseType(msg[Messages::sk_LabelRoot]) != expectedType)
		{
			throw MessageParseException();
		}
	}

	~VoteAppMessage()
	{}

	virtual std::string GetMessageCategoryStr() const override { return sk_ValueCat; }
	virtual std::string GetMessageTypeStr() const = 0;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override
	{
		Json::Value& parent = Messages::GetJsonMsg(outJson);

		parent[sk_LabelRoot] = Json::objectValue;
		parent[sk_LabelRoot][sk_LabelType] = GetMessageTypeStr();

		return parent[sk_LabelRoot];
	}
};

class VoteAppHandshake : public VoteAppMessage
{
public:
	static constexpr char const sk_ValueType[] = "RAHandshake";

public:
	VoteAppHandshake() = delete;
	VoteAppHandshake(const std::string& senderID) :
		VoteAppMessage(senderID)
	{}

	explicit VoteAppHandshake(const Json::Value& msg) :
		VoteAppMessage(msg, sk_ValueType)
	{}

	virtual ~VoteAppHandshake() {}

	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override
	{
		Json::Value& parent = VoteAppMessage::GetJsonMsg(outJson);
		return parent;
	}
};

class VoteAppHandshakeAck : public VoteAppMessage
{
public:
	static constexpr char const sk_LabelSelfReport[] = "SelfReport";

	static constexpr char const sk_ValueType[] = "RAHandshakeAck";

	static std::string ParseSelfRAReport(const Json::Value& DecentRoot)
	{
		if (DecentRoot.isMember(sk_LabelSelfReport) && DecentRoot[sk_LabelSelfReport].isString())
		{
			return DecentRoot[sk_LabelSelfReport].asString();
		}
		throw MessageParseException();
	}

public:
	VoteAppHandshakeAck() = delete;
	VoteAppHandshakeAck(const std::string& senderID, const std::string& selfRAReport) :
		VoteAppMessage(senderID),
		m_selfRAReport(selfRAReport)
	{}

	explicit VoteAppHandshakeAck(const Json::Value& msg) :
		VoteAppMessage(msg, sk_ValueType),
		m_selfRAReport(ParseSelfRAReport(msg[Messages::sk_LabelRoot][VoteAppMessage::sk_LabelRoot]))
	{}

	virtual ~VoteAppHandshakeAck() {}

	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }

	virtual const std::string& GetSelfRAReport() const { return m_selfRAReport; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override
	{
		Json::Value& parent = VoteAppMessage::GetJsonMsg(outJson);
		parent[sk_LabelSelfReport] = m_selfRAReport;
		return parent;
	}

private:
	const std::string m_selfRAReport;
};
