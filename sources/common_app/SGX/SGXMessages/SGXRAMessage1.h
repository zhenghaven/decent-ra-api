#pragma once

#include "SGXRAMessage.h"

#include <sgx_key_exchange.h>

class SGXRAMessage1 : public SGXRASPMessage
{
public:
	static constexpr char const sk_LabelData[] = "Msg1Data";

	static constexpr char const sk_ValueType[] = "MSG1_SEND";

	static sgx_ra_msg1_t ParseMsg1Data(const Json::Value& SGXRASPRoot);

public:
	SGXRAMessage1() = delete;
	SGXRAMessage1(const std::string& senderID, const sgx_ra_msg1_t& msg1Data);
	SGXRAMessage1(const Json::Value& msg);
	~SGXRAMessage1();

	virtual std::string GetMessageTypeStr() const override;

	const sgx_ra_msg1_t& GetMsg1Data() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const sgx_ra_msg1_t m_msg1Data;
};
