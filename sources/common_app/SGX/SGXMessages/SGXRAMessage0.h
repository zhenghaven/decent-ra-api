#pragma once

#include "SGXRAMessage.h"

class SGXRAMessage0Send : public SGXRASPMessage
{
public:
	static constexpr char const sk_LabelExGroupId[] = "ExGroupID";

	static constexpr char const sk_ValueType[] = "MSG0_SEND";

	static uint32_t ParseExGroupID(const Json::Value& SGXRASPRoot);

public:
	SGXRAMessage0Send() = delete;
	SGXRAMessage0Send(const std::string& senderID, uint32_t exGrpID);
	SGXRAMessage0Send(const Json::Value& msg);
	~SGXRAMessage0Send();

	virtual std::string GetMessageTypeStr() const override;

	uint32_t GetExtendedGroupID() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const uint32_t m_exGrpID;
};


class SGXRAMessage0Resp : public SGXRAClientMessage
{
public:
	static constexpr char const sk_LabelPubKey[] = "PublicKey";

	static constexpr char const sk_ValueType[] = "MSG0_RESP";

	static std::string ParsePublicKey(const Json::Value& SGXRAClientRoot);

public:
	SGXRAMessage0Resp() = delete;
	SGXRAMessage0Resp(const std::string& senderID, const std::string& pubKeyBase64);
	SGXRAMessage0Resp(const Json::Value& msg);
	~SGXRAMessage0Resp();

	virtual std::string GetMessageTypeStr() const override;

	virtual std::string GetRAPubKey() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::string m_pubKey;
};
