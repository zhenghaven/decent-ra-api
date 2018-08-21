#pragma once

#include "SGXRAMessage.h"

#include <sgx_key_exchange.h>
#include <sgx_tcrypto.h>

#include "../../../common/SGX/sgx_ra_msg4.h"

class SGXRAMessage4 : public SGXRAClientMessage
{
public:
	static constexpr char* LABEL_DATA = "Msg4Data";
	static constexpr char* LABEL_SIGN = "Msg4Sign";

	static constexpr char* VALUE_TYPE = "MSG4_RESP";

	static sgx_ra_msg4_t ParseMsg4Data(const Json::Value& SGXRASPRoot);
	static sgx_ec256_signature_t ParseMsg4Sign(const Json::Value& SGXRASPRoot);

public:
	SGXRAMessage4() = delete;
	SGXRAMessage4(const std::string& senderID, const sgx_ra_msg4_t& msg4Data, const sgx_ec256_signature_t& signature);
	SGXRAMessage4(const Json::Value& msg);
	~SGXRAMessage4();

	virtual std::string GetMessageTypeStr() const override;

	const sgx_ra_msg4_t& GetMsg4Data() const;

	const sgx_ec256_signature_t& GetMsg4Signature() const;

protected:
	virtual Json::Value& GetJsonMsg(Json::Value& outJson) const override;

private:
	const sgx_ra_msg4_t m_msg4Data;
	const sgx_ec256_signature_t m_signature;
};
