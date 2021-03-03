#include "RaProcessorSp.h"

#include <cstdint>
#include <cstring>

#include <vector>
#include <map>

#include <sgx_key_exchange.h>

#include <cppcodec/base64_default_rfc4648.hpp>

#include <mbedTLScpp/DefaultRbg.hpp>
#include <mbedTLScpp/Hash.hpp>
#include <mbedTLScpp/Cmac.hpp>
#include <mbedTLScpp/X509Cert.hpp>

#include "../Common.h"
#include "../make_unique.h"
#include "../consttime_memequal.h"

#include "../Crypto/AesGcmPacker.hpp"

#include "../SGX/Ckdf.h"
#include "../SGX/IasReportCert.h"

#include "sgx_structs.h"
#include "IasReport.h"
#include "IasConnector.h"
#include "SgxCryptoConversions.h"
#include "RuntimeError.h"

using namespace Decent;
using namespace Decent::Sgx;
using namespace Decent::Ias;
using namespace Decent::Tools;

namespace
{
	static std::string ConstructNonce(size_t size)
	{
		size_t dataSize = (size / 4) * 3;
		std::vector<uint8_t> randData(dataSize, 0);

#ifndef SIMULATING_ENCLAVE
		mbedTLScpp::DefaultRbg rand;
		rand.Rand(randData.data(), randData.size());
#endif // SIMULATING_ENCLAVE

		return cppcodec::base64_rfc4648::encode(randData);
	}
}

const RaProcessorSp::SgxReportDataVerifier RaProcessorSp::sk_defaultRpDataVrfy([](const sgx_report_data_t& initData, const sgx_report_data_t& expected) -> bool
{
#ifndef SIMULATING_ENCLAVE
	return consttime_memequal(&initData, &expected, sizeof(sgx_report_data_t)) == 1;
#else
	return true;
#endif // SIMULATING_ENCLAVE
});

RaProcessorSp::RaProcessorSp(
	const void* const iasConnectorPtr,
	std::shared_ptr<const PKeyType> mySignKey,
	std::shared_ptr<const sgx_spid_t> spidPtr,
	SgxReportDataVerifier rpDataVrfy,
	SgxQuoteVerifier quoteVrfy,
	const sgx_ra_config& raConfig) :
	m_raConfig(raConfig),
	m_spid(spidPtr),
	m_iasConnectorPtr(iasConnectorPtr),
	m_mySignKey(mySignKey),
	m_encrKeyPair(),
	m_myEncrKey(),
	m_peerEncrKey(),
	m_nonce(),
	m_smk(),
	m_mk(),
	m_sk(),
	m_vk(),
	m_rpDataVrfy(rpDataVrfy),
	m_quoteVrfy(quoteVrfy),
	m_iasReport(),
	m_isAttested(false),
	m_iasReportStr(),
	m_reportCert(),
	m_reportSign()
{}

RaProcessorSp::~RaProcessorSp()
{}

RaProcessorSp::RaProcessorSp(RaProcessorSp && other) :
	m_raConfig(std::move(other.m_raConfig)),
	m_spid(std::move(other.m_spid)),
	m_iasConnectorPtr(other.m_iasConnectorPtr),
	m_mySignKey(std::move(other.m_mySignKey)),
	m_encrKeyPair(std::move(other.m_encrKeyPair)),
	m_myEncrKey(std::move(other.m_myEncrKey)),
	m_peerEncrKey(std::move(other.m_peerEncrKey)),
	m_nonce(std::move(other.m_nonce)),
	m_smk(std::move(other.m_smk)),
	m_mk(std::move(other.m_mk)),
	m_sk(std::move(other.m_sk)),
	m_vk(std::move(other.m_vk)),
	m_rpDataVrfy(std::move(other.m_rpDataVrfy)),
	m_quoteVrfy(std::move(other.m_quoteVrfy)),
	m_iasReport(std::move(other.m_iasReport)),
	m_isAttested(other.m_isAttested),
	m_iasReportStr(std::move(other.m_iasReportStr)),
	m_reportCert(std::move(other.m_reportCert)),
	m_reportSign(std::move(other.m_reportSign))
{
	other.m_iasConnectorPtr = nullptr;
	other.m_isAttested = false;
}

void RaProcessorSp::Init()
{
	if (m_mySignKey == nullptr)
	{
		throw InvalidArgumentException("RaProcessorSp::Init - Signing key provided are invalid.");
	}

	m_encrKeyPair = Tools::make_unique<PKeyType>(PKeyType::Generate());
	if (m_encrKeyPair == nullptr)
	{
		throw RuntimeException("RaProcessorSp::Init - Failed to generate encryption key.");
	}

	m_nonce = ConstructNonce(IAS_REQUEST_NONCE_SIZE);

	m_iasReport = Tools::make_unique<sgx_ias_report_t>();

	std::array<uint8_t, 32> tmpX;
	std::array<uint8_t, 32> tmpY;
	std::tie(tmpX, tmpY, std::ignore) = m_encrKeyPair->GetPublicBytes();
	std::copy(tmpX.begin(), tmpX.end(), m_myEncrKey.x);
	std::copy(tmpY.begin(), tmpY.end(), m_myEncrKey.y);

	if (!Ias::CheckRaConfigValidaty(m_raConfig))
	{
		throw RuntimeException("RA config given to RaProcessorSp::Init is invalid.");
	}

	if (!CheckKeyDerivationFuncId(m_raConfig.ckdf_id))
	{
		throw RuntimeException("Key derivation function ID in RA config given to RaProcessorSp::Init is invalid.");
	}
}

void RaProcessorSp::ProcessMsg0(const sgx_ra_msg0s_t & msg0s, sgx_ra_msg0r_t & msg0r)
{
	if (!CheckExGrpId(msg0s.extended_grp_id))
	{
		throw RuntimeException("RA extension group ID given by the RA responder is not supported.");
	}

	GetMsg0r(msg0r);
}

void RaProcessorSp::ProcessMsg1(const sgx_ra_msg1_t & msg1, std::vector<uint8_t>& msg2)
{
	using namespace mbedTLScpp;

	SetPeerEncrPubKey(reinterpret_cast<const general_secp256r1_public_t&>(msg1.g_a));

	msg2.resize(sizeof(sgx_ra_msg2_t));
	sgx_ra_msg2_t& msg2Ref = *reinterpret_cast<sgx_ra_msg2_t*>(msg2.data());

	memcpy(&(msg2Ref.g_b), &m_myEncrKey, sizeof(sgx_ec256_public_t));
	memcpy(&(msg2Ref.spid), m_spid.get(), sizeof(sgx_spid_t));
	msg2Ref.quote_type = m_raConfig.linkable_sign;
	msg2Ref.kdf_id = m_raConfig.ckdf_id;

	Hash<HashType::SHA256> hashToBeSigned = Hasher<HashType::SHA256>().Calc(
		CtnFullR(m_myEncrKey.x),
		CtnFullR(m_myEncrKey.y),
		CtnFullR(m_peerEncrKey.x),
		CtnFullR(m_peerEncrKey.y)
	);

	PKeyType::KArray r, s;
	std::tie(r, s) = m_mySignKey->Sign(hashToBeSigned);
	std::memcpy(msg2Ref.sign_gb_ga.x, r.data(), r.size());
	std::memcpy(msg2Ref.sign_gb_ga.y, s.data(), s.size());

	const size_t cmac_size = offsetof(sgx_ra_msg2_t, mac);
	std::vector<uint8_t> tmpCmacData(cmac_size);
	std::memcpy(tmpCmacData.data(), &(msg2Ref.g_b), tmpCmacData.size());

	auto cmacRes = Cmacer< CipherType::AES, 128, CipherMode::ECB>(CtnFullR(m_smk)).Calc(
		CtnFullR(tmpCmacData)
	);
	static_assert(std::tuple_size<decltype(cmacRes)>::value == sizeof(msg2Ref.mac), "Size doesn't match");
	std::memcpy(msg2Ref.mac, cmacRes.data(), cmacRes.size());

	std::string revcList;
	if (!StatConnector::GetRevocationList(m_iasConnectorPtr, msg1.gid, revcList))
	{
		throw RuntimeException("RaProcessorSp::ProcessMsg1 failed to get revocation list.");
	}

	std::vector<uint8_t> revcListBin = cppcodec::base64_rfc4648::decode(revcList);

	msg2Ref.sig_rl_size = static_cast<uint32_t>(revcListBin.size());
	msg2.insert(msg2.end(), revcListBin.begin(), revcListBin.end());
}

void RaProcessorSp::ProcessMsg3(const sgx_ra_msg3_t & msg3, size_t msg3Len, std::vector<uint8_t> & msg4Pack,
	sgx_report_data_t * outOriRD)
{
	using namespace mbedTLScpp;

	if (msg3Len < sizeof(sgx_ra_msg3_t))
	{
		throw InvalidArgumentException("RaProcessorSp::ProcessMsg3 - Size of message 3 recieved is too small.");
	}

	if (!consttime_memequal(&(m_peerEncrKey), &msg3.g_a, sizeof(sgx_ec256_public_t)))
	{
		throw RuntimeException("RaProcessorSp::ProcessMsg3 failed to verify MSG 3.");
	}
	
	//Make sure that msg3_size is bigger than sgx_mac_t.
	uint32_t mac_size = static_cast<uint32_t>(msg3Len - sizeof(sgx_mac_t));
	const uint8_t *p_msg3_cmaced = reinterpret_cast<const uint8_t*>(&msg3) + sizeof(sgx_mac_t);
	std::vector<uint8_t> tmpCamcData(p_msg3_cmaced, p_msg3_cmaced + mac_size);

	auto calcMac = Cmacer<CipherType::AES, 128, CipherMode::ECB>(CtnFullR(m_smk)).Calc(
		CtnFullR(tmpCamcData)
	);
	if (!consttime_memequal(calcMac.data(), msg3.mac, sizeof(msg3.mac)))
	{
		throw RuntimeException("RaProcessorSp::ProcessMsg3 failed to verify MSG 3.");
	}

	//std::memcpy(&spCTX.m_secProp, &msg3.ps_sec_prop, sizeof(sgx_ps_sec_prop_desc_t));

	//const sgx_quote_t* p_quote = reinterpret_cast<const sgx_quote_t *>(msg3->quote);

	sgx_report_data_t report_data = { 0 };

	// Verify the report_data in the Quote matches the expected value.
	// The first 32 bytes of report_data are SHA256 HASH of {ga|gb|vk}.
	// The second 32 bytes of report_data are set to zero.
	Hash<HashType::SHA256> reportDataHash = Hasher<HashType::SHA256>().Calc(
		CtnFullR(m_peerEncrKey.x),
		CtnFullR(m_peerEncrKey.y),
		CtnFullR(m_myEncrKey.x),
		CtnFullR(m_myEncrKey.y),
		CtnFullR(m_vk)
	);

	std::copy(reportDataHash.m_data.begin(), reportDataHash.m_data.end(), report_data.d);

	if (outOriRD)
	{
		std::memcpy(outOriRD, &report_data, sizeof(sgx_report_data_t));
	}

	const sgx_quote_t& quoteInMsg3 = reinterpret_cast<const sgx_quote_t&>(msg3.quote);

	do
	{
		if (!StatConnector::GetQuoteReport(m_iasConnectorPtr, msg3, msg3Len, m_nonce, m_raConfig.enable_pse,
			m_iasReportStr, m_reportSign, m_reportCert))
		{
			break;
		}

		X509Cert trustedIasCert = X509Cert::FromPEM(Ias::gsk_IasReportCert);
		X509Cert reportCertChain = X509Cert::FromPEM(m_reportCert);

		reportCertChain.ShrinkChain(trustedIasCert);

		m_reportCert = reportCertChain.GetPemChain();

		if (!CheckIasReport(*m_iasReport, m_iasReportStr, m_reportCert, m_reportSign, report_data) ||
#ifndef SIMULATING_ENCLAVE
			!consttime_memequal(&quoteInMsg3, &m_iasReport->m_quote, sizeof(sgx_quote_t) - sizeof(sgx_quote_t::signature_len))
#else
			false
#endif // !SIMULATING_ENCLAVE
			)
		{
			break;
		}

		if (m_raConfig.enable_pse)
		{
			Hash<HashType::SHA256> pseHash = Hasher<HashType::SHA256>().Calc(
				CtnFullR(msg3.ps_sec_prop.sgx_ps_sec_prop_desc)
			);

			if (!consttime_memequal(pseHash.data(), &m_iasReport->m_pse_hash, pseHash.size()))
			{
				break;
			}
		}

		m_isAttested = true;
	} while (false);

	sgx_ra_msg4_t msg4;
	std::memcpy(&msg4.report, m_iasReport.get(), sizeof(*m_iasReport));
	msg4.is_accepted = m_isAttested ? 1 : 0;

	std::vector<uint8_t> msg4Bin(sizeof(msg4));
	std::memcpy(msg4Bin.data(), &msg4, msg4Bin.size());

	std::tie(msg4Pack, std::ignore) =  Crypto::AesGcmPacker(CtnFullR(GetSK()), 1024).Pack(
		CtnFullR(gsk_emptyCtn),
		CtnFullR(gsk_emptyCtn),
		CtnFullR(msg4Bin),
		CtnFullR(GetMK())
	);

	if (!m_isAttested)
	{
		throw RuntimeException("RaProcessorSp::ProcessMsg3 rejects the quote; SGX RA failed.");
	}
}

const sgx_ra_config & RaProcessorSp::GetRaConfig() const
{
	return m_raConfig;
}

bool RaProcessorSp::IsAttested() const
{
	return m_isAttested;
}

std::unique_ptr<sgx_ias_report_t> RaProcessorSp::ReleaseIasReport()
{
	return std::move(m_iasReport);
}

const mbedTLScpp::SKey<128>& RaProcessorSp::GetSK() const
{
	return m_sk;
}

const mbedTLScpp::SKey<128>& RaProcessorSp::GetMK() const
{
	return m_mk;
}

void RaProcessorSp::GetMsg0r(sgx_ra_msg0r_t & msg0r)
{
	msg0r.ra_config = m_raConfig;

	std::array<uint8_t, 32> tmpX;
	std::array<uint8_t, 32> tmpY;
	std::tie(tmpX, tmpY, std::ignore) = m_mySignKey->GetPublicBytes();
	std::copy(tmpX.begin(), tmpX.end(), msg0r.sp_pub_key.gx);
	std::copy(tmpY.begin(), tmpY.end(), msg0r.sp_pub_key.gy);
}

const std::string & RaProcessorSp::GetIasReportStr() const
{
	return m_iasReportStr;
}

const std::string & RaProcessorSp::GetIasReportCert() const
{
	return m_reportCert;
}

const std::string & RaProcessorSp::GetIasReportSign() const
{
	return m_reportSign;
}

bool RaProcessorSp::CheckExGrpId(const uint32_t id) const
{
	return id == 0;
}

bool RaProcessorSp::CheckKeyDerivationFuncId(const uint16_t id) const
{
	return id == SGX_DEFAULT_AES_CMAC_KDF_ID;
}

void RaProcessorSp::SetPeerEncrPubKey(const general_secp256r1_public_t & inEncrPubKey)
{
	using namespace mbedTLScpp;

	m_peerEncrKey = inEncrPubKey;

	PPubKeyType peerEncrKey = PPubKeyType::FromBytes(inEncrPubKey.x, inEncrPubKey.y);

	auto sharedKey = m_encrKeyPair->DeriveSharedKey(peerEncrKey);

	m_smk = Ckdf<CipherType::AES, 128, CipherMode::ECB>(CtnFullR(sharedKey), "SMK");
	m_mk  = Ckdf<CipherType::AES, 128, CipherMode::ECB>(CtnFullR(sharedKey), "MK");
	m_sk  = Ckdf<CipherType::AES, 128, CipherMode::ECB>(CtnFullR(sharedKey), "SK");
	m_vk  = Ckdf<CipherType::AES, 128, CipherMode::ECB>(CtnFullR(sharedKey), "VK");
}

bool RaProcessorSp::CheckIasReport(sgx_ias_report_t & outIasReport,
	const std::string & iasReportStr, const std::string & reportCert, const std::string & reportSign,
	const sgx_report_data_t & oriRD) const
{
	if (!m_rpDataVrfy || !m_quoteVrfy)
	{
		return false;
	}

	auto quoteVerifier = [this, oriRD](const sgx_ias_report_t & iasReport) -> bool
	{
		return m_rpDataVrfy(oriRD, iasReport.m_quote.report_body.report_data) &&
			m_quoteVrfy(iasReport.m_quote);
	};

	return ParseAndVerifyIasReport(outIasReport, iasReportStr, reportCert, reportSign, m_nonce.c_str(), m_raConfig, quoteVerifier);
}
