//#if ENCLAVE_PLATFORM_SGX

#include "../Tools/Crypto.h"
#include "Crypto.h"

#include <iterator>
#include <exception>

#include <sgx_utils.h>
#include <sgx_trts.h>
#include <sgx_attributes.h>

#include "../../Common/Common.h"
#include "../../Common/RuntimeException.h"

#include "../../Common/MbedTls/Kdf.h"

//These are came from SGX SDK:
#define FLAGS_NON_SECURITY_BITS     (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY| SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK     (~FLAGS_NON_SECURITY_BITS)

#define MISC_NON_SECURITY_BITS      0x0FFFFFFF  /* bit[27:0]: have no security implications */
#define TSEAL_DEFAULT_MISCMASK      (~MISC_NON_SECURITY_BITS)

using namespace Decent;
using namespace Decent::Tools;

static_assert(sizeof(KeyRecoverMeta::m_keyId) == sizeof(sgx_key_request_t::key_id), 
	"The size of Key ID dosen't match SGX SDK. Probably caused by a SDK update.");
static_assert(sizeof(KeyRecoverMeta::m_CpuSvn) == sizeof(sgx_key_request_t::cpu_svn), 
	"The size of CPU SVN dosen't match SGX SDK. Probably caused by a SDK update.");
static_assert(sizeof(KeyRecoverMeta::m_IsvSvn) == sizeof(sgx_key_request_t::isv_svn), 
	"The size of ISV SVN dosen't match SGX SDK. Probably caused by a SDK update.");
static_assert(sizeof(KeyRecoverMeta) == (sizeof(KeyRecoverMeta::m_keyId) + sizeof(KeyRecoverMeta::m_CpuSvn) + sizeof(KeyRecoverMeta::m_IsvSvn)), 
	"KeyRecoverMeta struct isn't packed, may cause error since current implmentation relies on it.");

namespace
{
	static sgx_report_t ConstructSelfSgxReport()
	{
		sgx_report_t res;
		if (sgx_create_report(nullptr, nullptr, &res) != SGX_SUCCESS)
		{
			LOGW("Failed to create self report!");
			throw RuntimeException("Failed to create self report!");
		}

		return res;
	}
}

void detail::DeriveKey(KeyType keyType, KeyPolicy keyPolicy, general_128bit_key & outKey, const KeyRecoverMeta & meta)
{
	sgx_key_request_t keyReq;
	memset(&keyReq, 0, sizeof(sgx_key_request_t));

	switch (keyType)
	{
	case KeyType::EInitToken:
		keyReq.key_name = SGX_KEYSELECT_EINITTOKEN;
		break;
	case KeyType::Provision:
		keyReq.key_name = SGX_KEYSELECT_PROVISION;
		break;
	case KeyType::ProvisionSeal:
		keyReq.key_name = SGX_KEYSELECT_PROVISION_SEAL;
		break;
	case KeyType::Report:
		keyReq.key_name = SGX_KEYSELECT_REPORT;
		break;
	case KeyType::Seal:
		keyReq.key_name = SGX_KEYSELECT_SEAL;
		break;
	default:
		throw RuntimeException("Invalid parameter for function Tools::DeriveKey!");
	}

	switch (keyPolicy)
	{
	case KeyPolicy::ByMrEnclave:
		keyReq.key_policy = SGX_KEYPOLICY_MRENCLAVE;
		break;
	case KeyPolicy::ByMrSigner:
		keyReq.key_policy = SGX_KEYPOLICY_MRSIGNER;
		break;
	case KeyPolicy::ByMrEnclaveAndMrSigner:
		keyReq.key_policy = SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER;
		break;
	default:
		throw RuntimeException("Invalid parameter for function Tools::DeriveKey!");
		break;
	}

	memcpy(&keyReq.key_id, meta.m_keyId, sizeof(sgx_key_id_t));
	memcpy(&keyReq.cpu_svn, meta.m_CpuSvn, sizeof(sgx_cpu_svn_t));
	memcpy(&keyReq.isv_svn, &meta.m_IsvSvn, sizeof(sgx_isv_svn_t));

	keyReq.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
	keyReq.attribute_mask.xfrm = 0x0;

	keyReq.misc_mask = TSEAL_DEFAULT_MISCMASK;

	if (sgx_get_key(&keyReq, &outKey) != SGX_SUCCESS)
	{
		throw RuntimeException("Failed to get derived key from SGX!");
	}
}

void Tools::DeriveKey(KeyType keyType, KeyPolicy keyPolicy, const std::string & label, General128BitKey outKey, const KeyRecoverMeta & meta)
{
	general_128bit_key initialKey = { 0 };
	detail::DeriveKey(keyType, keyPolicy, initialKey, meta);

	MbedTlsObj::HKDF(MbedTlsObj::HashType::SHA256, initialKey, label, meta.m_keyId, outKey);
}

void Tools::GenNewKeyRecoverMeta(KeyRecoverMeta & outMeta, bool isGenKeyId)
{
	if (isGenKeyId && sgx_read_rand(outMeta.m_keyId, sizeof(KeyRecoverMeta::m_keyId)) != SGX_SUCCESS)
	{
		LOGW("Failed to generate key ID!");
		throw RuntimeException("Failed to generate key ID!");
	}
	memcpy(outMeta.m_CpuSvn, &SgxGetSelfReport().body.cpu_svn, sizeof(KeyRecoverMeta::m_CpuSvn));
	outMeta.m_IsvSvn = SgxGetSelfReport().body.isv_svn;
}

const sgx_report_t & Tools::SgxGetSelfReport()
{
	static const sgx_report_t selfReport = ConstructSelfSgxReport();

	return selfReport;
}

const std::vector<uint8_t>& Tools::GetSelfHash()
{
	static const std::vector<uint8_t> gsk_selfHash(std::begin(SgxGetSelfReport().body.mr_enclave.m), std::end(SgxGetSelfReport().body.mr_enclave.m));

	return gsk_selfHash;
}

//#endif //ENCLAVE_PLATFORM_SGX
