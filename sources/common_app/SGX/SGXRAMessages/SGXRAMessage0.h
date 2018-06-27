#pragma once

#include "SGXRAMessage.h"

#include <json/json.h>

class SGXRAMessage0Send : public SGXRAMessage
{
public:
	SGXRAMessage0Send() = delete;
	SGXRAMessage0Send(const std::string& senderID, uint32_t exGrpID);
	SGXRAMessage0Send(Json::Value& msg);
	~SGXRAMessage0Send();

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	uint32_t GetExtendedGroupID() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	uint32_t m_exGrpID;
};


class SGXRAMessage0Resp : public SGXRAMessage
{
public:
	SGXRAMessage0Resp() = delete;
	SGXRAMessage0Resp(const std::string& senderID, const std::string& pubKeyBase64);
	SGXRAMessage0Resp(Json::Value& msg);
	~SGXRAMessage0Resp();

	virtual std::string GetMessgaeSubTypeStr() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	virtual std::string GetRAPubKey() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	std::string m_pubKey;
};
