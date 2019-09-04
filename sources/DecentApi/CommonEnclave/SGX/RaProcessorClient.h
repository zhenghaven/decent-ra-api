#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <functional>

#include "../../Common/GeneralKeyTypes.h"

typedef struct _sgx_ra_msg0s_t sgx_ra_msg0s_t;
typedef struct _sgx_ra_msg0r_t sgx_ra_msg0r_t;
typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _ra_msg3_t sgx_ra_msg3_t;
typedef struct _sgx_ra_msg4_t sgx_ra_msg4_t;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ra_config sgx_ra_config;
typedef struct _sgx_ias_report_t sgx_ias_report_t;

namespace Decent
{
	namespace Sgx
	{
		class RaProcessorClient
		{
		public: //static members:
			typedef std::function<bool(const sgx_ec256_public_t&)> SpSignPubKeyVerifier;
			typedef std::function<bool(const sgx_ra_config&)> RaConfigChecker;
			static const SpSignPubKeyVerifier sk_acceptAnyPubKey;
			static const RaConfigChecker sk_acceptAnyRaConfig;

		public:
			RaProcessorClient(const uint64_t enclaveId, SpSignPubKeyVerifier signKeyVerifier, RaConfigChecker configChecker);
			virtual ~RaProcessorClient();

			RaProcessorClient(const RaProcessorClient& other) = delete;
			RaProcessorClient(RaProcessorClient&& other);

			virtual void GetMsg0s(sgx_ra_msg0s_t& msg0s);
			virtual void ProcessMsg0r(const sgx_ra_msg0r_t& msg0r, sgx_ra_msg1_t& msg1);
			virtual void ProcessMsg2(const sgx_ra_msg2_t& msg2, const size_t msg2Len, std::vector<uint8_t>& msg3);
			virtual void ProcessMsg4(const std::vector<uint8_t>& msg4Pack);

			bool IsAttested() const;
			const G128BitSecretKeyWrap& GetMK() const;
			const G128BitSecretKeyWrap& GetSK() const;
			std::unique_ptr<sgx_ias_report_t> ReleaseIasReport();

		protected:
			virtual void InitRaContext(const sgx_ra_config& raConfig, const sgx_ec256_public_t& pubKey);
			virtual void CloseRaContext();
			virtual bool CheckKeyDerivationFuncId(const uint16_t id) const;
			virtual void DeriveSharedKeys(G128BitSecretKeyWrap& mk, G128BitSecretKeyWrap& sk);
			virtual void GetMsg1(sgx_ra_msg1_t& msg1);

			uint64_t m_enclaveId;
			uint32_t m_raCtxId;
			bool m_ctxInited;

		private:

			std::unique_ptr<sgx_ra_config> m_raConfig;
			std::unique_ptr<sgx_ec256_public_t> m_peerSignKey;
			G128BitSecretKeyWrap m_mk;
			G128BitSecretKeyWrap m_sk;
			std::unique_ptr<sgx_ias_report_t> m_iasReport;

			SpSignPubKeyVerifier m_signKeyVerifier;
			RaConfigChecker m_configChecker;
			bool m_isAttested;
		};
	}
}
