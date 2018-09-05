#pragma once

#include "SGXRAMessage.h"

#include <vector>
#include <cstdint>

//Forward Declarations:
struct _ra_msg2_t;
typedef _ra_msg2_t sgx_ra_msg2_t;

class SGXRAMessage2 : public SGXRAClientMessage
{
public:
	static constexpr char const sk_LabelData[] = "Msg2Data";

	static constexpr char const sk_ValueType[] = "MSG2_RESP";

	static std::vector<uint8_t> ParseMsg2Data(const Json::Value& SGXRASPRoot);

public:
	SGXRAMessage2() = delete;
	SGXRAMessage2(const std::string& senderID, const std::vector<uint8_t>& msg2Data);
	SGXRAMessage2(const Json::Value& msg);
	~SGXRAMessage2();

	virtual std::string GetMessageTypeStr() const override;

	const sgx_ra_msg2_t& GetMsg2() const;

	const std::vector<uint8_t>& GetMsg2Data() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const std::vector<uint8_t> m_msg2Data;
};
