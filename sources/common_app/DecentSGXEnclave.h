#pragma once

#include "SGXEnclave.h"
#include "../common/Decent.h"

class DecentSGXEnclave : public SGXEnclave
{
public:
	using SGXEnclave::SGXEnclave;

	~DecentSGXEnclave();

	virtual std::unique_ptr<Connection> AcceptRAConnection() override;
	virtual std::unique_ptr<Connection> RequestRA(uint32_t ipAddr, uint16_t portNum) override;
	virtual std::unique_ptr<Connection> RequestAppNodeConnection(uint32_t ipAddr, uint16_t portNum);


	virtual void SetDecentMode(DecentNodeMode inDecentMode) = 0;

	virtual DecentNodeMode GetDecentMode() = 0;

	virtual sgx_status_t GetProtocolSignKey(const std::string& id, sgx_ec256_private_t& outPriKey, sgx_aes_gcm_128bit_tag_t& outPriKeyMac, sgx_ec256_public_t& outPubKey, sgx_aes_gcm_128bit_tag_t& outPubKeyMac) = 0;
	virtual sgx_status_t GetProtocolEncrKey(const std::string& id, sgx_ec256_private_t& outPriKey, sgx_aes_gcm_128bit_tag_t& outPriKeyMac, sgx_ec256_public_t& outPubKey, sgx_aes_gcm_128bit_tag_t& outPubKeyMac) = 0;
	virtual sgx_status_t SetProtocolSignKey(const std::string& id, const sgx_ec256_private_t& inPriKey, const sgx_aes_gcm_128bit_tag_t& inPriKeyMac, const sgx_ec256_public_t& inPubKey, const sgx_aes_gcm_128bit_tag_t& inPubKeyMac) = 0;
	virtual sgx_status_t SetProtocolEncrKey(const std::string& id, const sgx_ec256_private_t& inPriKey, const sgx_aes_gcm_128bit_tag_t& inPriKeyMac, const sgx_ec256_public_t& inPubKey, const sgx_aes_gcm_128bit_tag_t& inPubKeyMac) = 0;
	virtual sgx_status_t GetProtocolKeySigned(const std::string& id, const sgx_ec256_public_t& inSignKey, const sgx_ec256_public_t& inEncrKey, sgx_ec256_signature_t& outSignSign, sgx_aes_gcm_128bit_tag_t& outSignSignMac, sgx_ec256_signature_t& outEncrSign, sgx_aes_gcm_128bit_tag_t& outEncrSignMac) = 0;
	virtual sgx_status_t SetKeySigns(const std::string& id, const sgx_ec256_signature_t& inSignSign, const sgx_aes_gcm_128bit_tag_t& inSignSignMac, const sgx_ec256_signature_t& inEncrSign, const sgx_aes_gcm_128bit_tag_t& inEncrSignMac) = 0;
	virtual void GetKeySigns(sgx_ec256_signature_t& outSignSign, sgx_ec256_signature_t& outEncrSign) = 0;
	virtual sgx_status_t ProcessDecentMsg0(const std::string& id, const sgx_ec256_public_t& inSignKey, const sgx_ec256_signature_t& inSignSign, const sgx_ec256_public_t& inEncrKey, const sgx_ec256_signature_t& inEncrSign) = 0;

protected:

private:
	virtual std::unique_ptr<Connection> AcceptRootNodeRAConnection();
	virtual std::unique_ptr<Connection> RequestRootNodeRA(uint32_t ipAddr, uint16_t portNum);

	virtual std::unique_ptr<Connection> AcceptAppNodeConnection();
};
