#pragma once

#include "../Messages.h"

class DecentMessage : public Messages
{
public:
	static constexpr char sk_LabelRoot[] = "Decent";
	static constexpr char sk_LabelType[] = "Type";

	static constexpr char sk_ValueCat[] = "Decent"; // = sk_LabelRoot;

	static std::string ParseType(const Json::Value& MsgRootContent);

public:
	DecentMessage() = delete;
	DecentMessage(const std::string& senderID);
	DecentMessage(const Json::Value& msg, const char* expectedType);
	~DecentMessage();

	virtual std::string GetMessageCategoryStr() const override;
	virtual std::string GetMessageTypeStr() const = 0;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:

};

class DecentErrMsg : public DecentMessage
{
public:
	static constexpr char sk_LabelErrMsg[] = "ErrorMsg";

	static constexpr char sk_ValueType[] = "Error";

	static std::string ParseErrorMsg(const Json::Value& DecentRoot);

public:
	DecentErrMsg() = delete;
	DecentErrMsg(const std::string& senderID, const std::string& errStr);
	DecentErrMsg(const Json::Value& msg);
	virtual ~DecentErrMsg();

	virtual std::string GetMessageTypeStr() const override;

	const std::string& GetErrStr() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_errStr;
};

class DecentRAHandshake : public DecentMessage
{
public:
	static constexpr char sk_ValueType[] = "RAHandshake";

public:
	DecentRAHandshake() = delete;
	explicit DecentRAHandshake(const std::string& senderID);
	explicit DecentRAHandshake(const Json::Value& msg);
	virtual ~DecentRAHandshake();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
};

class DecentRAHandshakeAck : public DecentMessage
{
public:
	static constexpr char sk_LabelSelfReport[] = "SelfReport";

	static constexpr char sk_ValueType[] = "RAHandshakeAck";

	static std::string ParseSelfRAReport(const Json::Value& DecentRoot);

public:
	DecentRAHandshakeAck() = delete;
	explicit DecentRAHandshakeAck(const std::string& senderID, const std::string& selfRAReport);
	explicit DecentRAHandshakeAck(const Json::Value& msg);
	virtual ~DecentRAHandshakeAck();

	virtual std::string GetMessageTypeStr() const override;

	virtual const std::string& GetSelfRAReport() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_selfRAReport;
};

class DecentProtocolKeyReq : public DecentMessage
{
public:
	static constexpr char sk_ValueType[] = "ProtoKeyReq";

public:
	DecentProtocolKeyReq() = delete;
	explicit DecentProtocolKeyReq(const std::string& senderID);
	explicit DecentProtocolKeyReq(const Json::Value& msg);
	virtual ~DecentProtocolKeyReq();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
};

class DecentTrustedMessage : public DecentMessage
{
public:
	static constexpr char sk_LabelTrustedMsg[] = "Msg";

	static constexpr char sk_ValueType[] = "TrustedMsg";

	static std::string ParseTrustedMsg(const Json::Value& DecentRoot);

public:
	DecentTrustedMessage() = delete;
	explicit DecentTrustedMessage(const std::string& senderID, const std::string& trustedMsg);
	explicit DecentTrustedMessage(const Json::Value& msg);
	virtual ~DecentTrustedMessage();

	virtual std::string GetMessageTypeStr() const override;

	virtual const std::string& GetTrustedMsg() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_trustedMsg;
};

