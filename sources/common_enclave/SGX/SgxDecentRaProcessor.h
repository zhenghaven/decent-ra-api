#pragma once

#include "SgxRaProcessorClient.h"
#include "../../common/SGX/SgxRaProcessorSp.h"

namespace SgxDecentRaProcessorSp
{
	extern const sgx_ra_config defaultDecentRaConfig;
	std::unique_ptr<SgxRaProcessorSp> GetSgxDecentRaProcessorSp(const void* const iasConnectorPtr, const sgx_ec256_public_t& peerSignkey);
}

class SgxDecentRaProcessorClient : public SgxRaProcessorClient
{
public:
	static const RaConfigChecker defaultDecentConfigChecker;

public:
	SgxDecentRaProcessorClient(const uint64_t enclaveId, SpSignPubKeyVerifier signKeyVerifier, RaConfigChecker configChecker);
	SgxDecentRaProcessorClient(const uint64_t enclaveId);
	virtual ~SgxDecentRaProcessorClient();

	SgxDecentRaProcessorClient(const SgxDecentRaProcessorClient& other) = delete;
	SgxDecentRaProcessorClient(SgxDecentRaProcessorClient&& other);

	virtual bool ProcessMsg2(const sgx_ra_msg2_t& msg2, const size_t msg2Len, std::vector<uint8_t>& msg3) override;

protected:
	virtual bool InitRaContext(const sgx_ra_config& raConfig, const sgx_ec256_public_t& pubKey) override;
	virtual void CloseRaContext() override;
	virtual bool GetMsg1(sgx_ra_msg1_t& msg1) override;
};
