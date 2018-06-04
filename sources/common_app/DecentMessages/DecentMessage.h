#pragma once

#include "../RAMessages.h"

class DecentMessage : public RAMessages
{
public:
	enum class Type
	{
		DECENT_MSG0 = 0,
		DECENT_KEY_REQ,
		ROOT_NODE_RESP,
		APPL_NODE_RESP,
		OTHER,
	};
public:
	DecentMessage() = delete;
	DecentMessage(const std::string& senderID);
	DecentMessage(Json::Value& msg);
	~DecentMessage();

	virtual std::string ToJsonString() const;

	virtual Type GetType() const = 0;

	virtual std::string GetMessgaeSubTypeStr() const = 0;

protected:

	static std::string GetMessageTypeStr(const Type t);

	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:

};