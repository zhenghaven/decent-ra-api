#pragma once

#include "../Messages.h"

class DecentMessage : public Messages
{
public:
	static constexpr char* LABEL_ROOT = "Decent";
	static constexpr char* LABEL_TYPE = "Type";

	static constexpr char* VALUE_CAT = LABEL_ROOT;

	static std::string ParseType(const Json::Value& MsgRootContent);

public:
	DecentMessage() = delete;
	DecentMessage(const std::string& senderID);
	DecentMessage(const Json::Value& msg);
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
	static constexpr char* LABEL_ERR_MSG = "ErrorMsg";

	static constexpr char* VALUE_TYPE = "Error";

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
	static constexpr char* VALUE_TYPE = "RAHandshake";

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
	static constexpr char* LABEL_SELF_REPORT = "SelfReport";

	static constexpr char* VALUE_TYPE = "RAHandshakeAck";

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
	static constexpr char* VALUE_TYPE = "ProtoKeyReq";

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
	static constexpr char* LABEL_TRUSTED_MSG = "Msg";

	static constexpr char* VALUE_TYPE = "TrustedMsg";

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

