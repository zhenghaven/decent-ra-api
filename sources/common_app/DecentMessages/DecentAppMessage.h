#pragma once

#include "../Messages.h"

class DecentAppMessage : public Messages
{
public:
	static constexpr char sk_LabelRoot[] = "DecentApp";
	static constexpr char sk_LabelType[] = "Type";

	static constexpr char sk_ValueCat[] = "DecentApp"; // = sk_LabelRoot;

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

class DecentAppTrustedMessage : public DecentAppMessage
{
public:
	static constexpr char sk_LabelTrustedMsg[] = "Msg";
	static constexpr char sk_LabelAppAttach[] = "AppAttach";

	static constexpr char sk_ValueType[] = "TrustedMsg";

	static std::string ParseTrustedMsg(const Json::Value& DecentAppRoot);
	static std::string ParseAppAttach(const Json::Value& DecentAppRoot);

public:
	DecentAppTrustedMessage() = delete;
	explicit DecentAppTrustedMessage(const std::string& senderID, const std::string& trustedMsg, const std::string& appAttach) :
		DecentAppMessage(senderID),
		m_trustedMsg(trustedMsg),
		m_appAttach(appAttach)
	{}

	explicit DecentAppTrustedMessage(const Json::Value& msg);
	virtual ~DecentAppTrustedMessage() {}

	virtual std::string GetMessageTypeStr() const override { return sk_ValueType; }

	virtual const std::string& GetTrustedMsg() const { return m_trustedMsg; }
	virtual const std::string& GetAppAttach() const { return m_appAttach; }

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_trustedMsg;
	const std::string m_appAttach;
};
