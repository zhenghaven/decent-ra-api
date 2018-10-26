#pragma once

#include <memory>
#include <string>
#include <functional>
#include <vector>

#include "../GeneralKeyTypes.h"
#include "sgx_structs.h"

typedef struct _sgx_ra_msg0r_t sgx_ra_msg0r_t;
typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _ra_msg3_t sgx_ra_msg3_t;
typedef struct _sgx_ra_msg4_t sgx_ra_msg4_t;
typedef struct _sgx_ias_report_t sgx_ias_report_t;
typedef struct _sgx_report_data_t sgx_report_data_t;
typedef struct _quote_t sgx_quote_t;
typedef struct _spid_t sgx_spid_t;

namespace MbedTlsObj
{
	class ECKeyPair;
}

class SgxRaProcessorSp
{
public:
	typedef std::function<bool(const sgx_report_data_t& initData, const sgx_report_data_t& expected)> SgxReportDataVerifier;
	typedef std::function<bool(const sgx_quote_t& quote)> SgxQuoteVerifier;
	static void SetSpid(const sgx_spid_t & spid);
	static const SgxReportDataVerifier sk_defaultRpDataVrfy;
	static const sgx_ra_config sk_defaultRaConfig;

public:
	SgxRaProcessorSp(const void* const iasConnectorPtr, const std::shared_ptr<const MbedTlsObj::ECKeyPair>& mySignKey, 
		const sgx_ra_config& raConfig, SgxReportDataVerifier rpDataVrfy, SgxQuoteVerifier quoteVrfy);

	virtual ~SgxRaProcessorSp();

	SgxRaProcessorSp(const SgxRaProcessorSp& other) = delete;
	SgxRaProcessorSp(SgxRaProcessorSp&& other);

	virtual bool Init();
	virtual bool ProcessMsg0(const sgx_ra_msg0s_t& msg0s, sgx_ra_msg0r_t& msg0r);
	virtual bool ProcessMsg1(const sgx_ra_msg1_t& msg1, std::vector<uint8_t>& msg2);
	virtual bool ProcessMsg3(const sgx_ra_msg3_t& msg3, size_t msg3Len, sgx_ra_msg4_t& msg4, sgx_report_data_t* outOriRD);

	const sgx_ra_config& GetRaConfig() const;
	bool IsAttested() const;
	sgx_ias_report_t* ReleaseIasReport();
	const General128BitKey& GetSK() const;
	const General128BitKey& GetMK() const;

	virtual bool GetMsg0r(sgx_ra_msg0r_t& msg0r);
	const std::string& GetIasReportStr() const;
	const std::string& GetIasReportCert() const;
	const std::string& GetIasReportSign() const;

protected:
	virtual bool CheckExGrpId(const uint32_t id) const;
	virtual bool CheckKeyDerivationFuncId(const uint16_t id) const;
	virtual bool CheckIasReport(sgx_ias_report_t& outIasReport, 
		const std::string& iasReportStr, const std::string& reportCert, const std::string& reportSign, 
		const sgx_report_data_t& oriRD) const;

	virtual bool SetPeerEncrPubKey(const general_secp256r1_public_t& inEncrPubKey);

	sgx_ra_config m_raConfig;

private:
	std::shared_ptr<const sgx_spid_t> m_spid;

	const void* m_iasConnectorPtr;
	std::shared_ptr<const MbedTlsObj::ECKeyPair> m_mySignKey;

	std::unique_ptr<MbedTlsObj::ECKeyPair> m_encrKeyPair;

	//Do not move the following members:
	general_secp256r1_public_t m_myEncrKey;
	general_secp256r1_public_t m_peerEncrKey;
	//End Do Not Move.

	std::string m_nonce;

	General128BitKey m_smk;
	General128BitKey m_mk;
	General128BitKey m_sk;
	General128BitKey m_vk;

	SgxReportDataVerifier m_rpDataVrfy;
	SgxQuoteVerifier m_quoteVrfy;
	std::unique_ptr<sgx_ias_report_t> m_iasReport;
	bool m_isAttested;

	std::string m_iasReportStr;
	std::string m_reportCert;
	std::string m_reportSign;
};
