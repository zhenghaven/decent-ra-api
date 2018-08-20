#pragma once

#include <sgx_quote.h>

#include "../DecentEnclave.h"
#include "SGXEnclaveServiceProvider.h"

class SGXDecentEnclave : public SGXEnclaveServiceProvider, public DecentEnclave
{
public:
	SGXDecentEnclave(const sgx_spid_t& spid, const std::string& enclavePath, IASConnector iasConnector, const std::string& tokenPath);
	SGXDecentEnclave(const sgx_spid_t& spid, const std::string& enclavePath, IASConnector iasConnector, const fs::path tokenPath);
	SGXDecentEnclave(const sgx_spid_t& spid, const std::string& enclavePath, IASConnector iasConnector, const KnownFolderType tokenLocType, const std::string& tokenFileName);

	~SGXDecentEnclave();

	//SGXEnclave methods:
	virtual sgx_status_t ProcessRAMsg0Resp(const std::string& ServerID, const sgx_ec256_public_t& inKey, int enablePSE, sgx_ra_context_t& outContextID, sgx_ra_msg1_t & outMsg1) override;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) override;
	virtual sgx_status_t ProcessRAMsg2(const std::string& ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t& inContextID) override;
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const std::vector<uint8_t> & inMsg3, const std::string& iasReport, const std::string& reportSign, const std::string& reportCertChain, sgx_ra_msg4_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign, sgx_report_data_t* outOriRD = nullptr) override;
	virtual sgx_status_t ProcessRAMsg4(const std::string& ServerID, const sgx_ra_msg4_t& inMsg4, const sgx_ec256_signature_t& inMsg4Sign, sgx_ra_context_t inContextID) override;

	//DecentEnclave methods:
	virtual void SetDecentMode(DecentNodeMode inDecentMode) override;
	virtual DecentNodeMode GetDecentMode() override;

	virtual bool CreateDecentSelfRAReport(std::string& outReport) override; 
	virtual bool ProcessDecentSelfRAReport(const std::string& inReport) override;
	virtual bool ProcessDecentTrustedMsg(const std::string& nodeID, const std::unique_ptr<Connection>& connection, const std::string& jsonMsg) override;

	virtual sgx_status_t TransitToDecentNode(const std::string& id, bool isSP) override;

	virtual sgx_status_t GetProtocolSignKey(const std::string& id, sgx_ec256_private_t& outPriKey, sgx_aes_gcm_128bit_tag_t& outPriKeyMac, sgx_ec256_public_t& outPubKey, sgx_aes_gcm_128bit_tag_t& outPubKeyMac) override;
	virtual sgx_status_t SetProtocolSignKey(const std::string& id, const sgx_ec256_private_t& inPriKey, const sgx_aes_gcm_128bit_tag_t& inPriKeyMac, const sgx_ec256_public_t& inPubKey, const sgx_aes_gcm_128bit_tag_t& inPubKeyMac) override;
	virtual sgx_status_t GetProtocolKeySigned(const std::string& id, const sgx_ec256_public_t& inSignKey, const sgx_ec256_public_t& inEncrKey, sgx_ec256_signature_t& outSignSign, sgx_aes_gcm_128bit_tag_t& outSignSignMac, sgx_ec256_signature_t& outEncrSign, sgx_aes_gcm_128bit_tag_t& outEncrSignMac) override;
	virtual sgx_status_t SetKeySigns(const std::string& id, const sgx_ec256_signature_t& inSignSign, const sgx_aes_gcm_128bit_tag_t& inSignSignMac, const sgx_ec256_signature_t& inEncrSign, const sgx_aes_gcm_128bit_tag_t& inEncrSignMac) override;
	virtual sgx_status_t ProcessDecentMsg0(const std::string& id, const sgx_ec256_public_t& inSignKey, const sgx_ec256_signature_t& inSignSign, const sgx_ec256_public_t& inEncrKey, const sgx_ec256_signature_t& inEncrSign) override;
};
