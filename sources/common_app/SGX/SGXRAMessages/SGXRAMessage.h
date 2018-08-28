#pragma once

#include "../../Messages.h"

namespace Json
{
	class Value;
}

class SGXRAClientMessage :  public Messages
{
public:
	static constexpr char* LABEL_ROOT = "SGXRAClient";
	static constexpr char* LABEL_TYPE = "Type";

	static constexpr char* VALUE_CAT  = LABEL_ROOT;

	static std::string ParseType(const Json::Value& MsgRootContent);

public:
	SGXRAClientMessage() = delete;
	SGXRAClientMessage(const std::string& senderID);
	SGXRAClientMessage(const Json::Value& msg, const char* expectedType);
	virtual ~SGXRAClientMessage();

	virtual std::string GetMessageCategoryStr() const override;
	virtual std::string GetMessageTypeStr() const = 0;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const;

private:

};

class SGXRASPMessage : public Messages
{
public:
	static constexpr char* LABEL_ROOT = "SGXRASP";
	static constexpr char* LABEL_TYPE = "Type";

	static constexpr char* VALUE_CAT = LABEL_ROOT;

	static std::string ParseType(const Json::Value& MsgRootContent);

public:
	SGXRASPMessage() = delete;
	SGXRASPMessage(const std::string& senderID);
	SGXRASPMessage(const Json::Value& msg, const char* expectedType);
	virtual ~SGXRASPMessage();

	virtual std::string GetMessageCategoryStr() const override;
	virtual std::string GetMessageTypeStr() const = 0;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const;

private:

};

class SGXRAClientErrMsg : public SGXRAClientMessage
{
public:
	static constexpr char* LABEL_ERR_MSG = "ErrorMsg";

	static constexpr char* VALUE_TYPE = "Error";

	static std::string ParseErrorMsg(const Json::Value& SGXRAClientRoot);

public:
	SGXRAClientErrMsg() = delete;
	SGXRAClientErrMsg(const std::string& senderID, const std::string& errStr);
	SGXRAClientErrMsg(const Json::Value& msg);
	~SGXRAClientErrMsg();

	virtual std::string GetMessageTypeStr() const override;

	const std::string& GetErrStr() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_errStr;
};

class SGXRASPErrMsg : public SGXRASPMessage
{
public:
	static constexpr char* LABEL_ERR_MSG = "ErrorMsg";

	static constexpr char* VALUE_TYPE = "Error";

	static std::string ParseErrorMsg(const Json::Value& SGXRASPRoot);

public:
	SGXRASPErrMsg() = delete;
	SGXRASPErrMsg(const std::string& senderID, const std::string& errStr);
	SGXRASPErrMsg(const Json::Value& msg);
	~SGXRASPErrMsg();

	virtual std::string GetMessageTypeStr() const override;

	const std::string& GetErrStr() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_errStr;
};
