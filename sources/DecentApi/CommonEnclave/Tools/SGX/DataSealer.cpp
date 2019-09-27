//#if ENCLAVE_PLATFORM_SGX

#include "../DataSealer.h"

#include <cstring>

#include <sgx_utils.h>
#include <sgx_attributes.h>

#include "../../../Common/Common.h"
#include "../../../Common/GeneralKeyTypes.h"
#include "../../../Common/RuntimeException.h"
#include "../../../Common/SGX/ErrorCode.h"
#include "../../../Common/MbedTls/Kdf.h"
#include "../../../Common/Ra/States.h"
#include "../../../Common/Ra/WhiteList/LoadedList.h"

#include "../Crypto.h"

//These are came from SGX SDK:
#define FLAGS_NON_SECURITY_BITS     (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY| SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK     (~FLAGS_NON_SECURITY_BITS)

#define MISC_NON_SECURITY_BITS      0x0FFFFFFF  /* bit[27:0]: have no security implications */
#define TSEAL_DEFAULT_MISCMASK      (~MISC_NON_SECURITY_BITS)

using namespace Decent;
using namespace Decent::MbedTlsObj;
using namespace Decent::Tools;
using namespace Decent::Tools::DataSealer;

namespace Decent
{
	namespace Sgx
	{
		const sgx_report_t& GetSelfSgxReport();
	}
}

namespace
{
	constexpr char gsk_sgxMetaLabel[] = "SGX";

	struct SgxSealKeyMeta
	{
		char m_label[sizeof(gsk_sgxMetaLabel)]; //24-bit
		uint8_t m_keyId[32];  //256-bit
		uint8_t m_CpuSvn[16]; //128-bit
		uint16_t m_IsvSvn; //16-bit
	};

	static_assert(sizeof(SgxSealKeyMeta::m_keyId) == sizeof(sgx_key_request_t::key_id),
		"The size of Key ID dosen't match SGX SDK. Probably caused by a SDK update.");
	static_assert(sizeof(SgxSealKeyMeta::m_CpuSvn) == sizeof(sgx_key_request_t::cpu_svn),
		"The size of CPU SVN dosen't match SGX SDK. Probably caused by a SDK update.");
	static_assert(sizeof(SgxSealKeyMeta::m_IsvSvn) == sizeof(sgx_key_request_t::isv_svn),
		"The size of ISV SVN dosen't match SGX SDK. Probably caused by a SDK update.");
	static_assert(sizeof(SgxSealKeyMeta) == (sizeof(SgxSealKeyMeta::m_keyId) + sizeof(SgxSealKeyMeta::m_CpuSvn) + sizeof(SgxSealKeyMeta::m_IsvSvn) + sizeof(gsk_sgxMetaLabel)),
		"KeyRecoverMeta struct isn't packed, may cause error since current implmentation may rely on it.");

	/**
	 * \brief	Values that represent SGX key types. Too SGX specific functionalities, and any type
	 * 			other than Seal key is not very useful for now, thus, we don't expose it to the API
	 * 			for now.
	 */
	enum class SgxKeyType
	{
		EInitToken,
		Provision,
		ProvisionSeal,
		Report,
		Seal,
	};

	static uint16_t GetSgxKeyPolicyNum(DataSealer::KeyPolicy keyPolicy)
	{
		switch (keyPolicy)
		{
		case DataSealer::KeyPolicy::ByMrEnclave:            return SGX_KEYPOLICY_MRENCLAVE;
		case DataSealer::KeyPolicy::ByMrSigner:             return SGX_KEYPOLICY_MRSIGNER;
		case DataSealer::KeyPolicy::ByMrEnclaveAndMrSigner: return SGX_KEYPOLICY_MRENCLAVE | SGX_KEYPOLICY_MRSIGNER;
		default:                                            throw Decent::RuntimeException("Invalid parameter for function SgxDeriveKey.");
		}
	}

	static uint16_t GetSgxKeyNameNum(SgxKeyType keyType)
	{
		switch (keyType)
		{
		case SgxKeyType::EInitToken:    return SGX_KEYSELECT_EINITTOKEN;
		case SgxKeyType::Provision:     return SGX_KEYSELECT_PROVISION;
		case SgxKeyType::ProvisionSeal: return SGX_KEYSELECT_PROVISION_SEAL;
		case SgxKeyType::Report:        return SGX_KEYSELECT_REPORT;
		case SgxKeyType::Seal:          return SGX_KEYSELECT_SEAL;
		default:                        throw Decent::RuntimeException("Invalid parameter for function SgxDeriveKey.");
		}
	}

	void SgxDeriveKey(SgxKeyType keyType, DataSealer::KeyPolicy keyPolicy, general_128bit_key & outKey, const SgxSealKeyMeta & meta)
	{
		if (!consttime_memequal(meta.m_label, gsk_sgxMetaLabel, sizeof(gsk_sgxMetaLabel)))
		{
			throw Decent::RuntimeException("Invalid metadata is given to function SgxDeriveKey.");
		}

		sgx_key_request_t keyReq;
		memset(&keyReq, 0, sizeof(sgx_key_request_t));

		keyReq.key_name = GetSgxKeyNameNum(keyType);

		keyReq.key_policy = GetSgxKeyPolicyNum(keyPolicy);

		memcpy(&keyReq.key_id, meta.m_keyId, sizeof(sgx_key_id_t));
		memcpy(&keyReq.cpu_svn, meta.m_CpuSvn, sizeof(sgx_cpu_svn_t));
		memcpy(&keyReq.isv_svn, &meta.m_IsvSvn, sizeof(sgx_isv_svn_t));

		keyReq.attribute_mask.flags = TSEAL_DEFAULT_FLAGSMASK;
		keyReq.attribute_mask.xfrm = 0x0;

		keyReq.misc_mask = TSEAL_DEFAULT_MISCMASK;

		sgx_status_t sgxRet = sgx_get_key(&keyReq, &outKey);
		if (sgxRet != SGX_SUCCESS)
		{
			throw Decent::RuntimeException(Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_get_key"));
		}
	}

	void SgxDeriveSealKey(KeyPolicy keyPolicy, G128BitSecretKeyWrap& outKey, const void* inMeta, const size_t inMetaSize)
	{
		if (inMetaSize != sizeof(SgxSealKeyMeta))
		{
			throw Decent::RuntimeException("Invalid metadata is given to function DeriveSealKey.");
		}
		const SgxSealKeyMeta& metaRef = *static_cast<const SgxSealKeyMeta*>(inMeta);

		general_128bit_key& keyRef = *reinterpret_cast<general_128bit_key*>(outKey.m_key.data());

		SgxDeriveKey(SgxKeyType::Seal, keyPolicy, keyRef, metaRef);
	}
}

void DataSealer::detail::DeriveSealKey(KeyPolicy keyPolicy, const Ra::States& decentState, const std::string& label, 
	void* outKey, const size_t expectedKeySize, const void* inMeta, const size_t inMetaSize, const std::vector<uint8_t>& salt)
{
	G128BitSecretKeyWrap rootSealKey;
	SgxDeriveSealKey(keyPolicy, rootSealKey, inMeta, inMetaSize);

	HKDF<HashType::SHA256>(rootSealKey.m_key, decentState.GetLoadedWhiteList().GetWhiteListHash() + label, salt, outKey, expectedKeySize);
}

std::vector<uint8_t> DataSealer::GenSealKeyRecoverMeta(bool isDefault)
{
	std::vector<uint8_t> res(sizeof(SgxSealKeyMeta), 0);
	SgxSealKeyMeta& metaRef = reinterpret_cast<SgxSealKeyMeta&>(*res.data());

	std::memcpy(metaRef.m_label, gsk_sgxMetaLabel, sizeof(gsk_sgxMetaLabel));

	if (isDefault)
	{
		return res;
	}

	SecureRand(metaRef.m_keyId, sizeof(SgxSealKeyMeta::m_keyId));

	std::memcpy(metaRef.m_CpuSvn, Sgx::GetSelfSgxReport().body.cpu_svn.svn, sizeof(SgxSealKeyMeta::m_CpuSvn));
	metaRef.m_IsvSvn = Sgx::GetSelfSgxReport().body.isv_svn;

	return res;
}

//#endif //ENCLAVE_PLATFORM_SGX
