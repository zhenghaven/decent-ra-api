#include "RaProcessor.h"

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/MbedTls/MbedTlsObjects.h"
#include "../../Common/MbedTls/MbedTlsHelpers.h"
#include "../../Common/Ra/States.h"
#include "../../Common/Ra/RaReport.h"
#include "../../Common/Ra/KeyContainer.h"
#include "../../Common/SGX/SgxCryptoConversions.h"
#include "../../Common/SGX/IasReport.h"

#include "../../CommonEnclave/Tools/Crypto.h"
#include "../../CommonEnclave/SGX/edl_decent_tools.h"

#include "DecentReplace/decent_tkey_exchange.h"
#include "edl_decent_ra_server.h"

using namespace Decent;
using namespace Decent::RaSgx;
using namespace Decent::Ra;

const Decent::Sgx::RaProcessorClient::RaConfigChecker RaProcessorClient::sk_acceptDefaultConfig(
	[](const sgx_ra_config& raConfig) -> bool
	{
		return Ias::CheckRaConfigEqual(raConfig, RaReport::sk_sgxDecentRaConfig);
	}
);

RaProcessorClient::RaProcessorClient(const uint64_t enclaveId, SpSignPubKeyVerifier signKeyVerifier, RaConfigChecker configChecker, const States& decentStates) :
	Decent::Sgx::RaProcessorClient(enclaveId, signKeyVerifier, configChecker),
	m_decentStates(decentStates)
{
}

RaProcessorClient::~RaProcessorClient()
{
}

RaProcessorClient::RaProcessorClient(RaProcessorClient && other) :
	Decent::Sgx::RaProcessorClient(std::forward<RaProcessorClient>(other)),
	m_decentStates(other.m_decentStates)
{
}

bool RaProcessorClient::ProcessMsg2(const sgx_ra_msg2_t & msg2, const size_t msg2Len, std::vector<uint8_t>& msg3)
{
	size_t retVal = 0;
	uint8_t* tmpMsg3 = nullptr;
	if (ocall_decent_ra_server_ra_proc_msg2(&retVal, m_enclaveId, m_raCtxId, &msg2, msg2Len, &tmpMsg3) != SGX_SUCCESS ||
		!retVal)
	{
		return false;
	}

	msg3.resize(retVal);
	std::copy(tmpMsg3, tmpMsg3 + retVal, msg3.begin());

	ocall_decent_tools_del_buf_uint8(tmpMsg3);

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
		[this](const sgx_report_data_t& initData, sgx_report_data_t& outData) -> bool
		{
			std::shared_ptr<const MbedTlsObj::ECKeyPublic> signPub = m_decentStates.GetKeyContainer().GetSignKeyPair();

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
	if (ocall_decent_ra_server_ra_get_msg1(&retVal, m_enclaveId, m_raCtxId, &msg1) != SGX_SUCCESS ||
		!retVal)
	{
		return false;
	}
	return true;
}

const Decent::Sgx::RaProcessorSp::SgxQuoteVerifier RaProcessorSp::defaultServerQuoteVerifier(
	[](const sgx_quote_t& quote) -> bool
{
	const std::vector<uint8_t>& decentHash = Decent::Tools::GetSelfHash();
	return sizeof(quote.report_body.mr_enclave) == decentHash.size() &&
		consttime_memequal(decentHash.data(), &quote.report_body.mr_enclave, decentHash.size());
}
);

std::unique_ptr<Decent::Sgx::RaProcessorSp> RaProcessorSp::GetSgxDecentRaProcessorSp(const void * const iasConnectorPtr,
	const sgx_ec256_public_t & peerSignkey, const States& decentStates)
{
	sgx_ec256_public_t signKey(peerSignkey);
	return Tools::make_unique<Sgx::RaProcessorSp>(iasConnectorPtr, decentStates.GetKeyContainer().GetSignKeyPair(),
		[signKey](const sgx_report_data_t& initData, const sgx_report_data_t& expected) -> bool
	{
		MbedTlsObj::ECKeyPublic pubKey = MbedTlsObj::ECKeyPublic::FromGeneral(SgxEc256Type2General(signKey));
		std::string pubKeyPem = pubKey.ToPubPemString();
		if (pubKeyPem.size() == 0)
		{
			return false;
		}
		return RaReport::DecentReportDataVerifier(pubKeyPem, initData.d, expected.d, sizeof(expected) / 2) &&
			consttime_memequal(initData.d + (sizeof(initData) / 2), expected.d + (sizeof(expected) / 2), sizeof(expected) / 2) == 1;
	},
		defaultServerQuoteVerifier,
		RaReport::sk_sgxDecentRaConfig);
}
