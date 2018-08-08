#pragma once

#include "../common_app/SGX/SGXEnclave.h"
#include "../common_app/SGX/SGXServiceProvider.h"
#include "../common_app/DecentEnclave.h"

class DecentSGXEnclaveImp : public SGXEnclave, public SGXServiceProvider, public DecentEnclave
{
public:
	DecentSGXEnclaveImp(const std::string& enclavePath, IASConnector iasConnector, const std::string& tokenPath);
	DecentSGXEnclaveImp(const std::string& enclavePath, IASConnector iasConnector, const fs::path tokenPath);
	DecentSGXEnclaveImp(const std::string& enclavePath, IASConnector iasConnector, const KnownFolderType tokenLocType, const std::string& tokenFileName);

	~DecentSGXEnclaveImp();
	
	virtual std::string GetRASenderID() const override;

	//SGXEnclave methods:
	virtual sgx_status_t GetRASignPubKey(sgx_ec256_public_t& outKey) override;
	virtual sgx_status_t GetRAEncrPubKey(sgx_ec256_public_t& outKey) override;

	virtual sgx_status_t InitClientRAEnvironment() override;
	virtual sgx_status_t InitSPRAEnvironment() override;
	virtual sgx_status_t GetIasReportNonce(const std::string & clientID, std::string& outNonce) override;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) override;
	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1) override;
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) override;
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const sgx_ra_msg2_t& inMsg2, const uint32_t& msg2Size, sgx_ra_msg3_t& outMsg3, std::vector<uint8_t>& outQuote, sgx_ra_context_t& inContextID) override;
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const sgx_ra_msg3_t& inMsg3, const uint32_t msg3Len, const std::string& iasReport, const std::string& reportSign, const std::string& reportCertChain, sgx_ra_msg4_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign) override;
	virtual sgx_status_t ProcessRAMsg4(const std::string& ServerID, const sgx_ra_msg4_t& inMsg4, const sgx_ec256_signature_t& inMsg4Sign, sgx_ra_context_t inContextID) override;
	virtual sgx_status_t TerminationClean() override;

	virtual sgx_status_t GetSimpleSecret(const std::string& id, uint64_t& secret, sgx_aes_gcm_128bit_tag_t& outSecretMac);
	virtual sgx_status_t ProcessSimpleSecret(const std::string& id, const uint64_t& secret, const sgx_aes_gcm_128bit_tag_t& inSecretMac);

	//DecentEnclave methods:
	virtual void SetDecentMode(DecentNodeMode inDecentMode) override;
	virtual DecentNodeMode GetDecentMode() override;

	virtual sgx_status_t GetProtocolSignKey(const std::string& id, sgx_ec256_private_t& outPriKey, sgx_aes_gcm_128bit_tag_t& outPriKeyMac, sgx_ec256_public_t& outPubKey, sgx_aes_gcm_128bit_tag_t& outPubKeyMac) override;
	virtual sgx_status_t GetProtocolEncrKey(const std::string& id, sgx_ec256_private_t& outPriKey, sgx_aes_gcm_128bit_tag_t& outPriKeyMac, sgx_ec256_public_t& outPubKey, sgx_aes_gcm_128bit_tag_t& outPubKeyMac) override;
	virtual sgx_status_t SetProtocolSignKey(const std::string& id, const sgx_ec256_private_t& inPriKey, const sgx_aes_gcm_128bit_tag_t& inPriKeyMac, const sgx_ec256_public_t& inPubKey, const sgx_aes_gcm_128bit_tag_t& inPubKeyMac) override;
	virtual sgx_status_t SetProtocolEncrKey(const std::string& id, const sgx_ec256_private_t& inPriKey, const sgx_aes_gcm_128bit_tag_t& inPriKeyMac, const sgx_ec256_public_t& inPubKey, const sgx_aes_gcm_128bit_tag_t& inPubKeyMac) override;
	virtual sgx_status_t GetProtocolKeySigned(const std::string& id, const sgx_ec256_public_t& inSignKey, const sgx_ec256_public_t& inEncrKey, sgx_ec256_signature_t& outSignSign, sgx_aes_gcm_128bit_tag_t& outSignSignMac, sgx_ec256_signature_t& outEncrSign, sgx_aes_gcm_128bit_tag_t& outEncrSignMac) override;
	virtual sgx_status_t SetKeySigns(const std::string& id, const sgx_ec256_signature_t& inSignSign, const sgx_aes_gcm_128bit_tag_t& inSignSignMac, const sgx_ec256_signature_t& inEncrSign, const sgx_aes_gcm_128bit_tag_t& inEncrSignMac) override;
	virtual void GetKeySigns(sgx_ec256_signature_t& outSignSign, sgx_ec256_signature_t& outEncrSign) override;
	virtual sgx_status_t ProcessDecentMsg0(const std::string& id, const sgx_ec256_public_t& inSignKey, const sgx_ec256_signature_t& inSignSign, const sgx_ec256_public_t& inEncrKey, const sgx_ec256_signature_t& inEncrSign) override;

private:
	std::string m_raSenderID;

};