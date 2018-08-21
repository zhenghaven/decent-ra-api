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
	DecentRAHandshake(const std::string& senderID);
	DecentRAHandshake(const Json::Value& msg);
	virtual ~DecentRAHandshake();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
};

class DecentRAHandshakeAck : public DecentMessage
{
public:
	static constexpr char* VALUE_TYPE = "RAHandshakeAck";

public:
	DecentRAHandshakeAck() = delete;
	DecentRAHandshakeAck(const std::string& senderID);
	DecentRAHandshakeAck(const Json::Value& msg);
	virtual ~DecentRAHandshakeAck();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
};

