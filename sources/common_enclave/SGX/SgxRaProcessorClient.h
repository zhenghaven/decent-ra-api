#pragma once

#include <cstdint>
#include <vector>
#include <memory>
#include <functional>

#include "../../common/GeneralKeyTypes.h"

typedef struct _sgx_ra_msg0r_t sgx_ra_msg0r_t;
typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _ra_msg3_t sgx_ra_msg3_t;
typedef struct _sgx_ra_msg4_t sgx_ra_msg4_t;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ra_config sgx_ra_config;
typedef struct _sgx_ias_report_t sgx_ias_report_t;

class SgxRaProcessorClient
{
public:
	typedef std::function<bool(const sgx_ec256_public_t& pubKey)> SpSignPubKeyVerifier;
	typedef std::function<bool(const sgx_ra_config& raConfig)> RaConfigChecker;
	static const SpSignPubKeyVerifier sk_acceptAnyPubKey;
	static const RaConfigChecker sk_acceptAnyRaConfig;

public:
	SgxRaProcessorClient(const uint64_t enclaveId, SpSignPubKeyVerifier signKeyVerifier, RaConfigChecker configChecker);
	virtual ~SgxRaProcessorClient();

	SgxRaProcessorClient(const SgxRaProcessorClient& other) = delete;
	SgxRaProcessorClient(SgxRaProcessorClient&& other);

	virtual bool ProcessMsg0r(const sgx_ra_msg0r_t& msg0r, sgx_ra_msg1_t& msg1);
	virtual bool ProcessMsg2(const sgx_ra_msg2_t& msg2, const size_t msg2Len, std::vector<uint8_t>& msg3);
	virtual bool ProcessMsg4(const sgx_ra_msg4_t& msg4);

	bool IsAttested() const;
	const General128BitKey& GetMK() const;
	const General128BitKey& GetSK() const;
	sgx_ias_report_t* ReleaseIasReport();

protected:
	virtual bool InitRaContext(const sgx_ra_config& raConfig, const sgx_ec256_public_t& pubKey);
	virtual void CloseRaContext();
	virtual bool CheckKeyDerivationFuncId(const uint16_t id) const;
	virtual bool DeriveSharedKeys(General128BitKey& mk, General128BitKey& sk);
	virtual bool GetMsg1(sgx_ra_msg1_t& msg1);

	uint64_t m_enclaveId;
	uint32_t m_raCtxId;
	bool m_ctxInited;

private:

	std::unique_ptr<sgx_ra_config> m_raConfig;
	std::unique_ptr<sgx_ec256_public_t> m_peerSignKey;
	General128BitKey m_mk;
	General128BitKey m_sk;
	std::unique_ptr<sgx_ias_report_t> m_iasReport;

	SpSignPubKeyVerifier m_signKeyVerifier;
	RaConfigChecker m_configChecker;
	bool m_isAttested;
};
