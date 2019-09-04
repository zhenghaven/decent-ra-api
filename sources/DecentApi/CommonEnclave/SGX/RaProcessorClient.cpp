#include "RaProcessorClient.h"

#include <sgx_tkey_exchange.h>

#include "../../Common/Common.h"
#include "../../Common/make_unique.h"
#include "../../Common/Ra/KeyContainer.h"
#include "../../Common/Tools/Crypto.h"
#include "../../Common/SGX/sgx_structs.h"
#include "../../Common/SGX/IasReport.h"
#include "../../Common/SGX/RuntimeError.h"

#include "../Tools/UntrustedBuffer.h"

#include "edl_decent_sgx_client.h"
#include "edl_decent_tools.h"

using namespace Decent;
using namespace Decent::Sgx;

const RaProcessorClient::SpSignPubKeyVerifier RaProcessorClient::sk_acceptAnyPubKey(
	[](const sgx_ec256_public_t& pubKey) -> bool
	{
		return true;
	}
);

const RaProcessorClient::RaConfigChecker RaProcessorClient::sk_acceptAnyRaConfig(
	[](const sgx_ra_config& raConfig) -> bool
	{
		return Ias::CheckRaConfigValidaty(raConfig);
	}
);

RaProcessorClient::RaProcessorClient(const uint64_t enclaveId, SpSignPubKeyVerifier signKeyVerifier, RaConfigChecker configChecker) :
	m_enclaveId(enclaveId),
	m_raCtxId(),
	m_ctxInited(false),
	m_raConfig(),
	m_peerSignKey(),
	m_mk(General128BitKey()),
	m_sk(General128BitKey()),
	m_iasReport(),
	m_signKeyVerifier(signKeyVerifier),
	m_configChecker(configChecker),
	m_isAttested(false)
{
}

RaProcessorClient::~RaProcessorClient()
{
	CloseRaContext();
}

RaProcessorClient::RaProcessorClient(RaProcessorClient && other) :
	m_enclaveId(other.m_enclaveId),
	m_raCtxId(other.m_raCtxId),
	m_ctxInited(other.m_ctxInited),
	m_raConfig(std::move(other.m_raConfig)),
	m_peerSignKey(std::move(other.m_peerSignKey)),
	m_mk(std::move(other.m_mk)),
	m_sk(std::move(other.m_sk)),
	m_iasReport(std::move(other.m_iasReport)),
	m_signKeyVerifier(std::move(other.m_signKeyVerifier)),
	m_configChecker(std::move(other.m_configChecker)),
	m_isAttested(other.m_isAttested)
{
	other.m_enclaveId = 0;
	other.m_raCtxId = 0;
	other.m_isAttested = false;
}

void RaProcessorClient::GetMsg0s(sgx_ra_msg0s_t & msg0s)
{
	int retVal = 0;
	DECENT_CHECK_SGX_FUNC_CALL_ERROR(ocall_decent_sgx_ra_get_msg0s, &retVal, &msg0s);

	if (!retVal)
	{
		throw RuntimeException("Failed to get SGX RA MSG 0 SEND.");
	}
}

void RaProcessorClient::ProcessMsg0r(const sgx_ra_msg0r_t & msg0r, sgx_ra_msg1_t & msg1)
{
	if (!m_configChecker(msg0r.ra_config) ||
		!CheckKeyDerivationFuncId(msg0r.ra_config.ckdf_id) ||
		!m_signKeyVerifier(msg0r.sp_pub_key))
	{
		throw RuntimeException("Failed to verify RA initiator's MSG 0.");
	}

	m_raConfig = Tools::make_unique<sgx_ra_config>(msg0r.ra_config);
	m_peerSignKey = Tools::make_unique<sgx_ec256_public_t>(msg0r.sp_pub_key);

	InitRaContext(msg0r.ra_config, msg0r.sp_pub_key);

	GetMsg1(msg1);
}

void RaProcessorClient::ProcessMsg2(const sgx_ra_msg2_t & msg2, const size_t msg2Len, std::vector<uint8_t>& msg3)
{
	size_t retVal = 0;
	uint8_t* tmpMsg3 = nullptr;

	DECENT_CHECK_SGX_FUNC_CALL_ERROR(ocall_decent_sgx_ra_proc_msg2, &retVal, m_enclaveId, m_raCtxId, &msg2, msg2Len, &tmpMsg3);

	if (!retVal)
	{
		throw RuntimeException("Function call to " "ocall_decent_sgx_ra_proc_msg2" " Failed.");
	}

	Tools::UntrustedBuffer msg3Buf(tmpMsg3, retVal);

	msg3 = msg3Buf.Read();
}

void RaProcessorClient::ProcessMsg4(const std::vector<uint8_t> & msg4Pack)
{
	DeriveSharedKeys(m_mk, m_sk);

	std::vector<uint8_t> meta;
	std::vector<uint8_t> msg4Bin;

	Tools::QuickAesGcmUnpack(GetSK().m_key, msg4Pack, GetMK().m_key, meta, msg4Bin, nullptr, 1024);

	if (msg4Bin.size() != sizeof(sgx_ra_msg4_t))
	{
		throw RuntimeException("Invalid SGX RA MSG4 received.");
	}

	sgx_ra_msg4_t msg4;
	std::memcpy(&msg4, msg4Bin.data(), sizeof(msg4));

	m_iasReport = Tools::make_unique<sgx_ias_report_t>();
	*m_iasReport = msg4.report;

	if (!msg4.is_accepted)
	{
		throw RuntimeException("Initiator rejected the SGX RA quote.");
	}

	m_isAttested = true;
}

bool RaProcessorClient::IsAttested() const
{
	return m_isAttested;
}

const G128BitSecretKeyWrap & RaProcessorClient::GetMK() const
{
	return m_mk;
}

const G128BitSecretKeyWrap & RaProcessorClient::GetSK() const
{
	return m_sk;
}

std::unique_ptr<sgx_ias_report_t> RaProcessorClient::ReleaseIasReport()
{
	return std::move(m_iasReport);
}

void RaProcessorClient::InitRaContext(const sgx_ra_config& raConfig, const sgx_ec256_public_t& pubKey)
{
	if (raConfig.enable_pse)
	{
		//int busy_retry_times = 2; do {} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		DECENT_CHECK_SGX_FUNC_CALL_ERROR(sgx_create_pse_session);
	}

	sgx_status_t ret = sgx_ra_init_ex(&pubKey, raConfig.enable_pse, nullptr, &m_raCtxId);

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
		sgx_ra_close(m_raCtxId);
	}
}

bool RaProcessorClient::CheckKeyDerivationFuncId(const uint16_t id) const
{
	return id == SGX_DEFAULT_AES_CMAC_KDF_ID;
}

void RaProcessorClient::DeriveSharedKeys(G128BitSecretKeyWrap & mk, G128BitSecretKeyWrap & sk)
{
	DECENT_CHECK_SGX_FUNC_CALL_ERROR(sgx_ra_get_keys, m_raCtxId, SGX_RA_KEY_SK, reinterpret_cast<sgx_ec_key_128bit_t*>(sk.m_key.data()));
	DECENT_CHECK_SGX_FUNC_CALL_ERROR(sgx_ra_get_keys, m_raCtxId, SGX_RA_KEY_MK, reinterpret_cast<sgx_ec_key_128bit_t*>(mk.m_key.data()));
}

void RaProcessorClient::GetMsg1(sgx_ra_msg1_t & msg1)
{
	int retVal = 0;
	DECENT_CHECK_SGX_FUNC_CALL_ERROR(ocall_decent_sgx_ra_get_msg1, &retVal, m_enclaveId, m_raCtxId, &msg1);
	
	if (!retVal)
	{
		throw RuntimeException("Function call to " "ocall_decent_sgx_ra_get_msg1" " Failed.");
	}
}

extern "C" sgx_status_t ecall_decent_sgx_client_enclave_init()
{
	return SGX_SUCCESS;
}

extern "C" void ecall_decent_sgx_client_enclave_terminate()
{
}
