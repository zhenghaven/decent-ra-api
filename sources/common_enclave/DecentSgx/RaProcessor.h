#pragma once

#include "../SGX/RaProcessorClient.h"
#include "../../common/SGX/RaProcessorSp.h"

namespace Decent
{
	namespace DecentSgx
	{
		namespace RaProcessorSp
		{
			extern const Sgx::RaProcessorSp::SgxQuoteVerifier defaultServerQuoteVerifier;
			std::unique_ptr<Sgx::RaProcessorSp> GetSgxDecentRaProcessorSp(const void* const iasConnectorPtr, const sgx_ec256_public_t& peerSignkey);
		}

		class RaProcessorClient : public Sgx::RaProcessorClient
		{
		public:
			static const RaConfigChecker sk_acceptDefaultConfig;

		public:
			RaProcessorClient(const uint64_t enclaveId, SpSignPubKeyVerifier signKeyVerifier, RaConfigChecker configChecker);
			virtual ~RaProcessorClient();

			RaProcessorClient(const RaProcessorClient& other) = delete;
			RaProcessorClient(RaProcessorClient&& other);

			virtual bool ProcessMsg2(const sgx_ra_msg2_t& msg2, const size_t msg2Len, std::vector<uint8_t>& msg3) override;

		protected:
			virtual bool InitRaContext(const sgx_ra_config& raConfig, const sgx_ec256_public_t& pubKey) override;
			virtual void CloseRaContext() override;
			virtual bool GetMsg1(sgx_ra_msg1_t& msg1) override;
		};
	}
}
