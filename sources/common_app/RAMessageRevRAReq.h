#pragma once

#include "RAMessages.h"

class RAMessageRevRAReq : public RAMessages
{
public:
	RAMessageRevRAReq() = delete;
	RAMessageRevRAReq(const std::string& senderID);
	RAMessageRevRAReq(Json::Value& msg);
	~RAMessageRevRAReq();

	virtual std::string ToJsonString() const;

	virtual std::string GetMessgaeSubTypeStr() const override;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:

};