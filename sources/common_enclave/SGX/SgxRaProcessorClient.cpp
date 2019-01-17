#include "SgxRaProcessorClient.h"

#include <sgx_tkey_exchange.h>

#include <Enclave_t.h>

#include "../../common/SGX/sgx_structs.h"
#include "../../common/CommonTool.h"
#include "../../common/Decent/KeyContainer.h"

const SgxRaProcessorClient::SpSignPubKeyVerifier SgxRaProcessorClient::sk_acceptAnyPubKey(
	[](const sgx_ec256_public_t& pubKey) -> bool
	{
		return true;
	}
);

const SgxRaProcessorClient::RaConfigChecker SgxRaProcessorClient::sk_acceptAnyRaConfig(
	[](const sgx_ra_config& raConfig) -> bool
	{
		if ((raConfig.linkable_sign != SGX_QUOTE_LINKABLE_SIGNATURE && raConfig.linkable_sign != SGX_QUOTE_UNLINKABLE_SIGNATURE) ||
			(raConfig.enable_pse != 0 && raConfig.enable_pse != 1) ||
			(raConfig.allow_ofd_enc != 0 && raConfig.allow_ofd_enc != 1) ||
			(raConfig.allow_ofd_pse != 0 && raConfig.allow_ofd_pse != 1))
		{
			return false;
		}

		return true;
	}
);

SgxRaProcessorClient::SgxRaProcessorClient(const uint64_t enclaveId, SpSignPubKeyVerifier signKeyVerifier, RaConfigChecker configChecker) :
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

SgxRaProcessorClient::~SgxRaProcessorClient()
{
	m_mk.fill(0);
	m_sk.fill(0);
	CloseRaContext();
}

SgxRaProcessorClient::SgxRaProcessorClient(SgxRaProcessorClient && other) :
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
	m_mk.fill(0);
	m_sk.fill(0);
	other.m_enclaveId = 0;
	other.m_raCtxId = 0;
	other.m_isAttested = false;
}

bool SgxRaProcessorClient::ProcessMsg0r(const sgx_ra_msg0r_t & msg0r, sgx_ra_msg1_t & msg1)
{
	if (!m_configChecker(msg0r.ra_config) ||
		!CheckKeyDerivationFuncId(msg0r.ra_config.ckdf_id) ||
		!m_signKeyVerifier(msg0r.sp_pub_key))
	{
		return false;
	}

	m_raConfig.reset(new sgx_ra_config(msg0r.ra_config));
	m_peerSignKey.reset(new sgx_ec256_public_t(msg0r.sp_pub_key));

	if (!InitRaContext(msg0r.ra_config, msg0r.sp_pub_key))
	{
		return false;
	}

	if (!GetMsg1(msg1))
	{
		return false;
	}

	return true;
}

bool SgxRaProcessorClient::ProcessMsg2(const sgx_ra_msg2_t & msg2, const size_t msg2Len, std::vector<uint8_t>& msg3)
{
	size_t retVal = 0;
	uint8_t* tmpMsg3 = nullptr;
	if (ocall_sgx_ra_proc_msg2(&retVal, m_enclaveId, m_raCtxId, &msg2, msg2Len, &tmpMsg3) != SGX_SUCCESS ||
		!retVal)
	{
		return false;
	}

	msg3.resize(retVal);
	std::copy(tmpMsg3, tmpMsg3 + retVal, msg3.begin());

	ocall_common_del_buf_uint8(tmpMsg3);

	return true;
}

bool SgxRaProcessorClient::ProcessMsg4(const sgx_ra_msg4_t & msg4)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;

	{
		sgx_ecc_state_handle_t eccState;
		enclaveRet = sgx_ecc256_open_context(&eccState);
		if (enclaveRet != SGX_SUCCESS)
		{
			return false;
		}

		uint8_t signVerifyRes = SGX_EC_INVALID_SIGNATURE;
		enclaveRet = sgx_ecdsa_verify(reinterpret_cast<const uint8_t*>(&msg4.is_accepted), 
			sizeof(msg4) - sizeof(sgx_ec256_signature_t), 
			m_peerSignKey.get(),
			const_cast<sgx_ec256_signature_t*>(&msg4.signature),
			&signVerifyRes, eccState);
		sgx_ecc256_close_context(eccState);

		if (enclaveRet != SGX_SUCCESS ||
			signVerifyRes != SGX_EC_VALID)
		{
			return false;
		}
	}

	if (!msg4.is_accepted)
	{
		return false;
	}

	if (!DeriveSharedKeys(m_mk, m_sk))
	{
		return false;
	}

	m_isAttested = true;
	return m_isAttested;
}

bool SgxRaProcessorClient::IsAttested() const
{
	return m_isAttested;
}

const General128BitKey & SgxRaProcessorClient::GetMK() const
{
	return m_mk;
}

const General128BitKey & SgxRaProcessorClient::GetSK() const
{
	return m_sk;
}

sgx_ias_report_t * SgxRaProcessorClient::ReleaseIasReport()
{
	return m_iasReport.release();
}

bool SgxRaProcessorClient::InitRaContext(const sgx_ra_config& raConfig, const sgx_ec256_public_t& pubKey)
{
	sgx_status_t ret;
	if (raConfig.enable_pse)
	{
		//int busy_retry_times = 2; do {} while (ret == SGX_ERROR_BUSY && busy_retry_times--);
		ret = sgx_create_pse_session();
		if (ret != SGX_SUCCESS)
			return false;
	}
	ret = sgx_ra_init_ex(&pubKey, raConfig.enable_pse, nullptr, &m_raCtxId);

	if (raConfig.enable_pse)
	{
		sgx_close_pse_session();
	}

	m_ctxInited = (ret == SGX_SUCCESS);
	return m_ctxInited;
}

void SgxRaProcessorClient::CloseRaContext()
{
	if (m_ctxInited)
	{
		sgx_ra_close(m_raCtxId);
	}
}

bool SgxRaProcessorClient::CheckKeyDerivationFuncId(const uint16_t id) const
{
	return id == SGX_DEFAULT_AES_CMAC_KDF_ID;
}

bool SgxRaProcessorClient::DeriveSharedKeys(General128BitKey & mk, General128BitKey & sk)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	enclaveRet = sgx_ra_get_keys(m_raCtxId, SGX_RA_KEY_SK, reinterpret_cast<sgx_ec_key_128bit_t*>(sk.data()));
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}
	enclaveRet = sgx_ra_get_keys(m_raCtxId, SGX_RA_KEY_MK, reinterpret_cast<sgx_ec_key_128bit_t*>(mk.data()));
	if (enclaveRet != SGX_SUCCESS)
	{
		return false;
	}
	return true;
}

bool SgxRaProcessorClient::GetMsg1(sgx_ra_msg1_t & msg1)
{
	int retVal = 0;
	if (ocall_sgx_ra_get_msg1(&retVal, m_enclaveId, m_raCtxId, &msg1) != SGX_SUCCESS ||
		!retVal)
	{
		return false;
	}
	return true;
}

extern "C" sgx_status_t ecall_enclave_init()
{
	return SGX_SUCCESS;
}

extern "C" void ecall_enclave_terminate()
{
}
