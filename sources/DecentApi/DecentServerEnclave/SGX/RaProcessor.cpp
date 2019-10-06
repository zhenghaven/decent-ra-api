#include "RaProcessor.h"

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/MbedTls/Hasher.h"
#include "../../Common/MbedTls/EcKey.h"
#include "../../Common/Ra/States.h"
#include "../../Common/Ra/RaReport.h"
#include "../../Common/Ra/KeyContainer.h"
#include "../../Common/SGX/IasReport.h"
#include "../../Common/SGX/RuntimeError.h"
#include "../../Common/SGX/SgxCryptoConversions.h"

#include "../../CommonEnclave/Tools/Crypto.h"
#include "../../CommonEnclave/Tools/UntrustedBuffer.h"
#include "../../CommonEnclave/SGX/edl_decent_tools.h"

#include "DecentReplace/decent_tkey_exchange.h"
#include "edl_decent_ra_server.h"

using namespace Decent;
using namespace Decent::Ra;
using namespace Decent::RaSgx;
using namespace Decent::MbedTlsObj;

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

void RaProcessorClient::ProcessMsg2(const sgx_ra_msg2_t & msg2, const size_t msg2Len, std::vector<uint8_t>& msg3)
{
	size_t retVal = 0;
	uint8_t* tmpMsg3 = nullptr;

	DECENT_CHECK_SGX_FUNC_CALL_ERROR(ocall_decent_ra_server_ra_proc_msg2, &retVal, m_enclaveId, m_raCtxId, &msg2, msg2Len, &tmpMsg3);

	if (!retVal)
	{
		throw RuntimeException("Function call to " "ocall_decent_ra_server_ra_proc_msg2" " Failed.");
	}

	Tools::UntrustedBuffer msg3Buf(tmpMsg3, retVal);

	msg3 = msg3Buf.Read();
}

void RaProcessorClient::InitRaContext(const sgx_ra_config & raConfig, const sgx_ec256_public_t & pubKey)
{
	using namespace Decent::MbedTlsObj;

	if (raConfig.enable_pse)
	{
		//int busy_retry_times = 2; do {} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		DECENT_CHECK_SGX_FUNC_CALL_ERROR(sgx_create_pse_session);
	}

	sgx_status_t ret = decent_ra_init_ex(&pubKey, raConfig.enable_pse, nullptr, 
		[this](const sgx_report_data_t& initData, sgx_report_data_t& outData) -> bool
		{
			auto signPub = m_decentStates.GetKeyContainer().GetSignKeyPair();

			std::string pubKeyPem = signPub->GetPublicPem();

			General256Hash reportDataHash;
			Hasher<HashType::SHA256>().Batched(reportDataHash,
				std::array<DataListItem, 2>
				{
					DataListItem{&initData, SGX_SHA256_HASH_SIZE},
					DataListItem{pubKeyPem.data(), pubKeyPem.size()},
				});

			std::memcpy(&outData, reportDataHash.data(), SGX_SHA256_HASH_SIZE);
			return true;
		},
		&m_raCtxId);

	if (raConfig.enable_pse)
	{
		sgx_close_pse_session();
	}

	DECENT_CHECK_SGX_STATUS_ERROR(ret, sgx_ra_init_ex);

	m_ctxInited = true;
}

void RaProcessorClient::CloseRaContext()
{
	if (m_ctxInited)
	{
		decent_ra_close(m_raCtxId);
	}
}

void RaProcessorClient::GetMsg1(sgx_ra_msg1_t & msg1)
{
	int retVal = 0;

	DECENT_CHECK_SGX_FUNC_CALL_ERROR(ocall_decent_ra_server_ra_get_msg1, &retVal, m_enclaveId, m_raCtxId, &msg1);

	if (!retVal)
	{
		throw RuntimeException("Function call to " "ocall_decent_ra_server_ra_get_msg1" " Failed.");
	}
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
	const MbedTlsObj::EcPublicKeyBase & peerSignkey, std::shared_ptr<const sgx_spid_t> spidPtr, const States& decentStates)
{
	std::string pubKeyPem = peerSignkey.GetPublicPem();

	return Tools::make_unique<Sgx::RaProcessorSp>(iasConnectorPtr, decentStates.GetKeyContainer().GetSignKeyPair(),
		spidPtr,
		[pubKeyPem](const sgx_report_data_t& initData, const sgx_report_data_t& expected) -> bool
	{
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
