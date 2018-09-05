#pragma once

#include "../../Messages.h"

namespace Json
{
	class Value;
}

class SGXRAClientMessage :  public Messages
{
public:
	static constexpr char const sk_LabelRoot[] = "SGXRAClient";
	static constexpr char const sk_LabelType[] = "Type";

	static constexpr char const sk_ValueCat[]  = "SGXRAClient"; // = sk_LabelRoot;

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
	static constexpr char const sk_LabelRoot[] = "SGXRASP";
	static constexpr char const sk_LabelType[] = "Type";

	static constexpr char const sk_ValueCat[] = "SGXRASP"; // = sk_LabelRoot;

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

class SGXRAClientErrMsg : public SGXRAClientMessage, public ErrorMessage
{
public:
	SGXRAClientErrMsg() = delete;
	SGXRAClientErrMsg(const std::string& senderID, const std::string& errStr);
	SGXRAClientErrMsg(const Json::Value& msg);
	~SGXRAClientErrMsg();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
};

class SGXRASPErrMsg : public SGXRASPMessage, public ErrorMessage
{
public:
	SGXRASPErrMsg() = delete;
	SGXRASPErrMsg(const std::string& senderID, const std::string& errStr);
	SGXRASPErrMsg(const Json::Value& msg);
	~SGXRASPErrMsg();

	virtual std::string GetMessageTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;
};
