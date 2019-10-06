#pragma once

#include "../../CommonEnclave/SGX/RaProcessorClient.h"
#include "../../Common/SGX/RaProcessorSp.h"

namespace Decent
{
	namespace Ra
	{
		class States;
	}

	namespace MbedTlsObj
	{
		class EcPublicKeyBase;
	}

	namespace RaSgx
	{
		namespace RaProcessorSp
		{
			extern const Sgx::RaProcessorSp::SgxQuoteVerifier defaultServerQuoteVerifier;
			std::unique_ptr<Sgx::RaProcessorSp> GetSgxDecentRaProcessorSp(const void* const iasConnectorPtr, const MbedTlsObj::EcPublicKeyBase& peerSignkey, std::shared_ptr<const sgx_spid_t> spidPtr, const Decent::Ra::States& decentStates);
		}

		class RaProcessorClient : public Sgx::RaProcessorClient
		{
		public:
			static const RaConfigChecker sk_acceptDefaultConfig;

		public:
			RaProcessorClient(const uint64_t enclaveId, SpSignPubKeyVerifier signKeyVerifier, RaConfigChecker configChecker, const Decent::Ra::States& decentStates);
			virtual ~RaProcessorClient();

			RaProcessorClient(const RaProcessorClient& other) = delete;
			RaProcessorClient(RaProcessorClient&& other);

			virtual void ProcessMsg2(const sgx_ra_msg2_t& msg2, const size_t msg2Len, std::vector<uint8_t>& msg3) override;

		protected:
			virtual void InitRaContext(const sgx_ra_config& raConfig, const sgx_ec256_public_t& pubKey) override;
			virtual void CloseRaContext() override;
			virtual void GetMsg1(sgx_ra_msg1_t& msg1) override;

		private:
			const Decent::Ra::States& m_decentStates;
		};
	}
}
