#pragma once

#include "SGXRAMessage.h"

#include <sgx_key_exchange.h>
#include <sgx_tcrypto.h>

#include "../../../common/SGX/ias_report.h"

class SGXRAMessage4 : public SGXRAClientMessage
{
public:
	static constexpr char sk_LabelData[] = "Msg4Data";
	static constexpr char sk_LabelSign[] = "Msg4Sign";

	static constexpr char sk_ValueType[] = "MSG4_RESP";

	static sgx_ias_report_t ParseMsg4Data(const Json::Value& SGXRASPRoot);
	static sgx_ec256_signature_t ParseMsg4Sign(const Json::Value& SGXRASPRoot);

public:
	SGXRAMessage4() = delete;
	SGXRAMessage4(const std::string& senderID, const sgx_ias_report_t& msg4Data, const sgx_ec256_signature_t& signature);
	SGXRAMessage4(const Json::Value& msg);
	~SGXRAMessage4();

	virtual std::string GetMessageTypeStr() const override;

	const sgx_ias_report_t& GetMsg4Data() const;

	const sgx_ec256_signature_t& GetMsg4Signature() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const sgx_ec256_signature_t m_signature;
	const sgx_ias_report_t m_msg4Data;
};
