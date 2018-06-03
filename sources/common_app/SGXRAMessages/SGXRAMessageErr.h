#pragma once

#include "SGXRAMessage.h"

#include <string>

#include <json/json.h>

class SGXRAMessageErr : public SGXRAMessage
{
public:
	SGXRAMessageErr() = delete;
	SGXRAMessageErr(const std::string& senderID, const std::string& errStr);
	SGXRAMessageErr(Json::Value& msg);
	~SGXRAMessageErr();

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	std::string GetErrStr() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	std::string m_errStr;
};
