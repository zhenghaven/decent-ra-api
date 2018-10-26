#include "../DecentCrypto.h"

#include <cstring>

#include <atomic>

#include <sgx_utils.h>
#include <sgx_dh.h>

#include <cppcodec/base64_rfc4648.hpp>

#include "../../common/DataCoding.h"
#include "../../common/DecentRAReport.h"

using namespace Decent;

namespace
{
	static sgx_report_t ConstructSgxReport()
	{
		sgx_report_t res;
		sgx_status_t enclaveRet = sgx_create_report(nullptr, nullptr, &res);
		if (enclaveRet != SGX_SUCCESS)
		{
			memset_s(&res, sizeof(res), 0, sizeof(res));
		}
		return res;
	}

	static const sgx_report_t gsk_selfReport(ConstructSgxReport());

	static General256Hash ConstructProgSelfHash()
	{
		General256Hash res = General256Hash();
		static_assert(res.size() == sizeof(sgx_measurement_t), "Measurement size doesn't match!");
		const sgx_measurement_t& enclaveHash = gsk_selfReport.body.mr_enclave;

		static_assert(res.size() == sizeof(enclaveHash.m), "Enclave hash size doesn't match!");

		std::copy(enclaveHash.m, enclaveHash.m + sizeof(enclaveHash.m), res.begin());

		return res;
	}

	static const Crypto::AppIdVerfier peerAppVerifier = [](const MbedTlsObj::ECKeyPublic& pubKey, const std::string& platformType, const std::string& appId) -> bool
	{
		if (platformType != Decent::RAReport::sk_ValueReportTypeSgx)
		{
			return false;
		}

		sgx_dh_session_enclave_identity_t identity;
		DeserializeStruct(identity, appId);

		return consttime_memequal(identity.mr_enclave.m, Crypto::GetGetProgSelfHash256().data(), Crypto::GetGetProgSelfHash256().size()) == 1;
	};


	static const Crypto::AppIdVerfier emptyAppVerifier = [](const MbedTlsObj::ECKeyPublic& pubKey, const std::string& platformType, const std::string& appId) -> bool
	{
		return true;
	};

	static std::shared_ptr<const TlsConfig> gsk_decentAppAppServerSideConfig;
	static std::shared_ptr<const TlsConfig> gsk_decentAppAppClientSideConfig;
	static std::shared_ptr<const TlsConfig> gsk_decentAppClientServerSideConfig;
}

const General256Hash& Crypto::GetGetProgSelfHash256()
{
	static const General256Hash hash = ConstructProgSelfHash();

	return hash;
}

const std::string& Crypto::GetProgSelfHashBase64()
{
	static const std::string hashBase64(cppcodec::base64_rfc4648::encode(Crypto::GetGetProgSelfHash256()));
	return hashBase64;
}

std::shared_ptr<const TlsConfig> Decent::Crypto::GetDecentAppAppServerSideConfig()
{
	return std::atomic_load(&gsk_decentAppAppServerSideConfig);
}

std::shared_ptr<const TlsConfig> Decent::Crypto::GetDecentAppAppClientSideConfig()
{
	return std::atomic_load(&gsk_decentAppAppClientSideConfig);
}

std::shared_ptr<const TlsConfig> Decent::Crypto::GetDecentAppClientServerSideConfig()
{
	return std::atomic_load(&gsk_decentAppClientServerSideConfig);
}

void Decent::Crypto::RefreshDecentAppAppServerSideConfig()
{
	std::shared_ptr<const TlsConfig> config(std::make_shared<TlsConfig>(peerAppVerifier, true));
	std::atomic_store(&gsk_decentAppAppServerSideConfig, config);
}

void Decent::Crypto::RefreshDecentAppAppClientSideConfig()
{
	std::shared_ptr<const TlsConfig> config(std::make_shared<TlsConfig>(peerAppVerifier, false));
	std::atomic_store(&gsk_decentAppAppClientSideConfig, config);
}

void Decent::Crypto::RefreshDecentAppClientServerSideConfig()
{
	std::shared_ptr<const TlsConfig> config(std::make_shared<TlsConfig>(emptyAppVerifier, true));
	std::atomic_store(&gsk_decentAppClientServerSideConfig, config);
}
