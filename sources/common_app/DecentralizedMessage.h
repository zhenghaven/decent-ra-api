#pragma once

#include "Messages.h"

class DecentralizedMessage : public Messages
{
public:
	static constexpr char* LABEL_ROOT = "Decentralized";
	static constexpr char* LABEL_TYPE = "Type";

	static constexpr char* VALUE_CAT = LABEL_ROOT;

	static std::string ParseType(const Json::Value& MsgRootContent);

public:
	DecentralizedMessage() = delete;
	DecentralizedMessage(const std::string& senderID);
	DecentralizedMessage(const Json::Value& msg, const char* expectedType);
	virtual ~DecentralizedMessage();

	virtual std::string GetMessageCategoryStr() const override;
	virtual std::string GetMessageTypeStr() const = 0;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:

};

class DecentralizedErrMsg : public DecentralizedMessage
{
public:
	static constexpr char* LABEL_ERR_MSG = "ErrorMsg";

	static constexpr char* VALUE_TYPE = "Error";

	static std::string ParseErrorMsg(const Json::Value& DecentralizedRoot);

public:
	DecentralizedErrMsg() = delete;
	DecentralizedErrMsg(const std::string& senderID, const std::string& errStr);
	DecentralizedErrMsg(const Json::Value& msg);
	virtual ~DecentralizedErrMsg();

	virtual std::string GetMessageTypeStr() const override;

	const std::string& GetErrStr() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_errStr;
};

class DecentralizedRAHandshake : public DecentralizedMessage
{
public:
	static constexpr char* VALUE_TYPE = "RAHandshake";

public:
	DecentralizedRAHandshake() = delete;
	DecentralizedRAHandshake(const std::string& senderID);
	DecentralizedRAHandshake(const Json::Value& msg);
	virtual ~DecentralizedRAHandshake();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
};

class DecentralizedRAHandshakeAck : public DecentralizedMessage
{
public:
	static constexpr char* VALUE_TYPE = "RAHandshakeAck";

public:
	DecentralizedRAHandshakeAck() = delete;
	DecentralizedRAHandshakeAck(const std::string& senderID);
	DecentralizedRAHandshakeAck(const Json::Value& msg);
	virtual ~DecentralizedRAHandshakeAck();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
};

class DecentralizedReverseReq : public DecentralizedMessage
{
public:
	static constexpr char* VALUE_TYPE = "ReverseReq";

public:
	DecentralizedReverseReq() = delete;
	DecentralizedReverseReq(const std::string& senderID);
	DecentralizedReverseReq(const Json::Value& msg);
	virtual ~DecentralizedReverseReq();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
};
