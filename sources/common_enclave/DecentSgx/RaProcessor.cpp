#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "RaProcessor.h"

#include <Enclave_t.h>

#include "../../common/CommonTool.h"
#include "../../common/MbedTls/MbedTlsObjects.h"
#include "../../common/MbedTls/MbedTlsHelpers.h"
#include "../../common/Ra/States.h"
#include "../../common/Ra/RaReport.h"
#include "../../common/Ra/KeyContainer.h"

#include "../../common/SGX/SgxCryptoConversions.h"

#include "../Ra/Crypto.h"

#include "DecentReplace/decent_tkey_exchange.h"

using namespace Decent::DecentSgx;
using namespace Decent::Ra;

const Decent::Sgx::RaProcessorClient::RaConfigChecker RaProcessorClient::sk_acceptDefaultConfig(
	[](const sgx_ra_config& raConfig) {
	const sgx_ra_config& cmp = RaReport::GetSgxDecentRaConfig();;
	return raConfig.enable_pse == cmp.enable_pse && 
		raConfig.linkable_sign == cmp.linkable_sign && 
		raConfig.ckdf_id == cmp.ckdf_id &&
		raConfig.allow_ofd_enc == cmp.allow_ofd_enc &&
		raConfig.allow_ofd_pse == cmp.allow_ofd_pse;
	}
);

RaProcessorClient::RaProcessorClient(const uint64_t enclaveId, SpSignPubKeyVerifier signKeyVerifier, RaConfigChecker configChecker) :
	Decent::Sgx::RaProcessorClient(enclaveId, signKeyVerifier, configChecker)
{
}

RaProcessorClient::~RaProcessorClient()
{
}

RaProcessorClient::RaProcessorClient(RaProcessorClient && other) :
	Decent::Sgx::RaProcessorClient(std::forward<RaProcessorClient>(other))
{
}

bool RaProcessorClient::ProcessMsg2(const sgx_ra_msg2_t & msg2, const size_t msg2Len, std::vector<uint8_t>& msg3)
{
	size_t retVal = 0;
	uint8_t* tmpMsg3 = nullptr;
	if (ocall_decent_ra_proc_msg2(&retVal, m_enclaveId, m_raCtxId, &msg2, msg2Len, &tmpMsg3) != SGX_SUCCESS ||
		!retVal)
	{
		return false;
	}

	msg3.resize(retVal);
	std::copy(tmpMsg3, tmpMsg3 + retVal, msg3.begin());

	ocall_common_del_buf_uint8(tmpMsg3);

	return true;
}

bool RaProcessorClient::InitRaContext(const sgx_ra_config & raConfig, const sgx_ec256_public_t & pubKey)
{
	sgx_status_t ret;
	if (raConfig.enable_pse)
	{
		//int busy_retry_times = 2; do {} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		ret = sgx_create_pse_session();
		if (ret != SGX_SUCCESS)
			return false;
	}
	ret = decent_ra_init_ex(&pubKey, raConfig.enable_pse, nullptr, 
		[](const sgx_report_data_t& initData, sgx_report_data_t& outData) -> bool
		{
			std::shared_ptr<const MbedTlsObj::ECKeyPublic> signPub = States::Get().GetKeyContainer().GetSignKeyPair();

			std::string pubKeyPem = signPub->ToPubPemString();
			if (pubKeyPem.size() == 0)
			{
				return false;
			}

			General256Hash reportDataHash;
			MbedTlsHelper::CalcHashSha256(MbedTlsHelper::hashListMode, {
				{&initData, SGX_SHA256_HASH_SIZE},
				{pubKeyPem.data(), pubKeyPem.size()},
				},
				reportDataHash);

			std::memcpy(&outData, reportDataHash.data(), SGX_SHA256_HASH_SIZE);
			return true;
		},
		&m_raCtxId);

	if (raConfig.enable_pse)
	{
		sgx_close_pse_session();
	}

	m_ctxInited = (ret == SGX_SUCCESS);
	return m_ctxInited;
}

void RaProcessorClient::CloseRaContext()
{
	if (m_ctxInited)
	{
		decent_ra_close(m_raCtxId);
	}
}

bool RaProcessorClient::GetMsg1(sgx_ra_msg1_t & msg1)
{
	int retVal = 0;
	if (ocall_decent_ra_get_msg1(&retVal, m_enclaveId, m_raCtxId, &msg1) != SGX_SUCCESS ||
		!retVal)
	{
		return false;
	}
	return true;
}

const Decent::Sgx::RaProcessorSp::SgxQuoteVerifier RaProcessorSp::defaultServerQuoteVerifier(
	[](const sgx_quote_t& quote) -> bool
{
	const std::vector<uint8_t>& decentHash = Decent::Crypto::GetSelfHash();
	return sizeof(quote.report_body.mr_enclave) == decentHash.size() &&
		consttime_memequal(decentHash.data(), &quote.report_body.mr_enclave, decentHash.size());
}
);

std::unique_ptr<Decent::Sgx::RaProcessorSp> RaProcessorSp::GetSgxDecentRaProcessorSp(const void * const iasConnectorPtr,
	const sgx_ec256_public_t & peerSignkey)
{
	sgx_ec256_public_t signKey(peerSignkey);
	return Common::make_unique<Sgx::RaProcessorSp>(iasConnectorPtr, States::Get().GetKeyContainer().GetSignKeyPair(),
		RaReport::GetSgxDecentRaConfig(),
		[signKey](const sgx_report_data_t& initData, const sgx_report_data_t& expected) -> bool
	{
		MbedTlsObj::ECKeyPublic pubKey(SgxEc256Type2General(signKey));
		std::string pubKeyPem = pubKey.ToPubPemString();
		if (pubKeyPem.size() == 0)
		{
			return false;
		}
		return RaReport::DecentReportDataVerifier(pubKeyPem, initData.d, expected.d, sizeof(expected) / 2) &&
			consttime_memequal(initData.d + (sizeof(initData) / 2), expected.d + (sizeof(expected) / 2), sizeof(expected) / 2) == 1;
	},
		defaultServerQuoteVerifier);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

