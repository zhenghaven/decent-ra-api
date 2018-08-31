#pragma once

#include "SGXRAMessage.h"

#include <vector>
#include <cstdint>

//Forward Declarations:
struct _ra_msg3_t;
typedef _ra_msg3_t sgx_ra_msg3_t;

class SGXRAMessage3 : public SGXRASPMessage
{
public:
	static constexpr char sk_LabelData[] = "Msg3Data";

	static constexpr char sk_ValueType[] = "MSG3_SEND";

	static std::vector<uint8_t> ParseMsg3Data(const Json::Value& SGXRASPRoot);

public:
	SGXRAMessage3() = delete;
	SGXRAMessage3(const std::string& senderID, const std::vector<uint8_t>& msg3Data);
	SGXRAMessage3(const Json::Value& msg);
	~SGXRAMessage3();

	virtual std::string GetMessageTypeStr() const override;

	const sgx_ra_msg3_t& GetMsg3() const;

	const std::vector<uint8_t>& GetMsg3Data() const;

	const uint32_t GetMsg3DataSize() const;

	std::string GetQuoteBase64() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::vector<uint8_t> m_msg3Data;
};
