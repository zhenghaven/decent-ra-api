#pragma once

#include "DecentMessage.h"

class DecentMessageErr : public DecentMessage
{
public:
	DecentMessageErr() = delete;
	DecentMessageErr(const std::string& senderID, const std::string& errMsg);
	DecentMessageErr(Json::Value& msg);
	~DecentMessageErr();

	virtual Type GetType() const override;

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual std::string GetErrorMsg() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	std::string m_errMsg;
};