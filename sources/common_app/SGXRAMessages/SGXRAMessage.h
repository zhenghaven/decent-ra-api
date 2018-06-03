#pragma once

#include <vector>
#include <cstdint>

#include <json/json.h>

#include "RAMessages.h"

class SGXRAMessage : public RAMessages
{
public:
	enum class Type 
	{
		MSG0_SEND = 0,
		MSG0_RESP,
		MSG1_SEND,
		//MSG1_RESP,
		//MSG2_SEND,
		MSG2_RESP,
		MSG3_SEND,
		//MSG3_RESP,
		//MSG4_SEND,
		MSG4_RESP,
		ERRO_RESP,
		OTHER,
	};

public:
	SGXRAMessage() = delete;
	SGXRAMessage(const std::string& senderID);
	SGXRAMessage(Json::Value& msg);
	~SGXRAMessage();

	virtual void SerializedMessage(std::vector<uint8_t>& outData) const;

	virtual std::string ToJsonString() const;

	virtual Type GetType() const = 0;

	virtual bool IsResp() const = 0;

	virtual std::string GetMessgaeSubTypeStr() const override;

	static Type GetTypeFromMessage(const std::string& msg);

	static const std::string sk_MessageClass;

protected:

	static std::string GetMessageTypeStr(const Type t);

	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:

};