#pragma once

#include "SGXRAMessage.h"

#include <json/json.h>

class SGXRAMessage0Send : public SGXRAMessage
{
public:
	SGXRAMessage0Send() = delete;
	SGXRAMessage0Send(uint32_t exGrpID);
	SGXRAMessage0Send(Json::Value& msg);
	~SGXRAMessage0Send();

	virtual std::string ToJsonString() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	uint32_t GetExtendedGroupID() const;

private:
	uint32_t m_exGrpID;
};


class SGXRAMessage0Resp : public SGXRAMessage
{
public:
	SGXRAMessage0Resp() = delete;
	SGXRAMessage0Resp(const bool isAccepted, const std::string& pubKeyBase64);
	SGXRAMessage0Resp(Json::Value& msg);
	~SGXRAMessage0Resp();

	virtual std::string ToJsonString() const override;

	virtual Type GetType() const override;
	virtual bool IsResp() const override;

	virtual bool IsAccepted() const;
	virtual std::string GetRAPubKey() const;

private:
	bool m_isAccepted;
	std::string m_pubKey;
};
