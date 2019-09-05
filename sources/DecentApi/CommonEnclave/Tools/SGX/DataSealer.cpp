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
		default:                                            throw RuntimeException("Invalid parameter for function SgxDeriveKey.");
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
		default:                        throw RuntimeException("Invalid parameter for function SgxDeriveKey.");
		}
	}

	void SgxDeriveKey(SgxKeyType keyType, DataSealer::KeyPolicy keyPolicy, general_128bit_key & outKey, const SgxSealKeyMeta & meta)
	{
		if (!consttime_memequal(meta.m_label, gsk_sgxMetaLabel, sizeof(gsk_sgxMetaLabel)))
		{
			throw RuntimeException("Invalid metadata is given to function SgxDeriveKey.");
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
			throw RuntimeException(Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_get_key"));
		}
	}

	void SgxDeriveSealKey(KeyPolicy keyPolicy, G128BitSecretKeyWrap& outKey, const void* inMeta, const size_t inMetaSize)
	{
		if (inMetaSize != sizeof(SgxSealKeyMeta))
		{
			throw RuntimeException("Invalid metadata is given to function DeriveSealKey.");
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

#if 0

////////////////////////////
//Data Sealing:
////////////////////////////

//Structure:
// Metadata Label           (PlainText) - 12  Bytes      -> 12   Bytes
// Metadata                 (PlainText) - 560 Bytes      -> 572  Bytes
// Additional Metadata size (Encrypted) - 4   Bytes      -> 576  Bytes
// Data size                (Encrypted) - 4   Bytes      -> 580  Bytes
// Additional Metadata      (Encrypted) - variable Size
// Data                     (Encrypted) - variable Size

namespace
{
	constexpr size_t gsk_sealedBlockSize = 4096; // block size is 4 KBytes.

	constexpr char   gsk_sgxSealedDataLabel[] = "SGX_Sealed_";

	constexpr size_t gsk_sgxSealMetaSize = sizeof(sgx_sealed_data_t);

	constexpr size_t gsk_decentSgxSealMetaSize = sizeof(gsk_sgxSealedDataLabel) + gsk_sgxSealMetaSize + sizeof(uint32_t) + sizeof(uint32_t);
	
	size_t GetTotalSealedBlockSize(const uint32_t inMetadataSize, const uint32_t inDataSize, uint32_t& encInSize, uint32_t& encOutSize, uint32_t& metaSize)
	{
		const size_t totalDataSize = gsk_decentSgxSealMetaSize + inMetadataSize + inDataSize;

		const size_t totalBlockNum =  static_cast<size_t>(std::ceil(static_cast<float>(totalDataSize) / gsk_sealedBlockSize));

		const size_t totalBlockSize = totalBlockNum * gsk_sealedBlockSize;

		if (totalBlockSize < totalDataSize)
		{
			throw RuntimeException("Unexpected ceiling calculation result.");
		}

		if (totalBlockSize > UINT32_MAX)
		{
			throw RuntimeException("The size of the data to be sealed is too big for SGX platform.");
		}

		const uint32_t padSize = static_cast<uint32_t>(totalBlockSize - totalDataSize);

		encInSize = static_cast<uint32_t>(sizeof(uint32_t) + sizeof(uint32_t)) + inMetadataSize + inDataSize + padSize;

		encOutSize = sgx_calc_sealed_data_size(0, encInSize);
		if (encOutSize == UINT32_MAX)
		{
			throw RuntimeException("Failed to calculate seal data size.");
		}
		metaSize = encOutSize - encInSize;

		const size_t res = sizeof(gsk_sgxSealedDataLabel) + encOutSize;

		EXCEPTION_ASSERT(totalBlockSize == res, "In function GetTotalSealedBlockSize, the total block size from our calculation is different from the SGX SDK.");

		return res;
	}
}

std::vector<uint8_t> DataSealer::detail::SealData(KeyPolicy keyPolicy, std::vector<uint8_t>& outMac, const void* inMetadata, const size_t inMetadataSize, const void * inData, const size_t inDataSize)
{
	if ((inMetadataSize > 0 && !inMetadata) || (inDataSize > 0 && !inData))
	{
		throw RuntimeException("Null pointer is given to function DataSealer::detail::SealData.");
	}

	if (inMetadataSize > UINT32_MAX || inDataSize > UINT32_MAX)
	{
		throw RuntimeException("The size of the data to be sealed is too big for SGX platform.");
	}

	const uint32_t metaSize32 = static_cast<uint32_t>(inMetadataSize);
	const uint32_t dataSize32 = static_cast<uint32_t>(inDataSize);

	const uint16_t key_policy = GetSgxKeyPolicyNum(keyPolicy);
	const sgx_attributes_t attribute_mask = { TSEAL_DEFAULT_FLAGSMASK /*flags*/, 0x0 /*xfrm*/ };
	const sgx_misc_select_t misc_mask = TSEAL_DEFAULT_MISCMASK;

	uint32_t encInSize = 0;
	uint32_t encOutSize = 0;
	uint32_t metaSize = 0;
	std::vector<uint8_t> res(
		GetTotalSealedBlockSize(metaSize32, dataSize32, encInSize, encOutSize, metaSize));

	//Construct plain text input package:
	std::vector<uint8_t> inputPkg(encInSize, 0);

	uint8_t* inputPkgPtr = inputPkg.data();
	uint32_t& inputPkgMetaSize = *reinterpret_cast<uint32_t*>(inputPkgPtr);
	uint32_t& inputPkgDataSize = *reinterpret_cast<uint32_t*>(inputPkgPtr += sizeof(uint32_t));
	uint8_t* inputPkgMeta = (inputPkgPtr += sizeof(uint32_t));
	uint8_t* inputPkgData = (inputPkgPtr += metaSize32);
	
	inputPkgMetaSize = metaSize32;
	inputPkgDataSize = dataSize32;
	std::memcpy(inputPkgMeta, inMetadata, metaSize32);
	std::memcpy(inputPkgData, inData, dataSize32);

	//Construct output package:
	//    Metadata Label:
	std::memcpy(&res[0], gsk_sgxSealedDataLabel, sizeof(gsk_sgxSealedDataLabel));

	uint8_t* outputpkgData = &res[sizeof(gsk_sgxSealedDataLabel)];
	sgx_sealed_data_t& sealedDataRef = *reinterpret_cast<sgx_sealed_data_t*>(outputpkgData);

	sgx_status_t sgxRet = sgx_seal_data_ex(key_policy, attribute_mask, misc_mask, 0, nullptr,
		static_cast<uint32_t>(inputPkg.size()), inputPkg.data(),
		encOutSize, &sealedDataRef);
	if (sgxRet != SGX_SUCCESS)
	{
		throw RuntimeException(Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_seal_data_ex"));
	}

	outMac.resize(0);
	outMac.reserve(sizeof(sealedDataRef.aes_data.payload_tag));
	outMac.insert(outMac.end(), std::begin(sealedDataRef.aes_data.payload_tag), std::end(sealedDataRef.aes_data.payload_tag));

	return res;
}

void DataSealer::detail::UnsealData(KeyPolicy keyPolicy, const void * inEncData, const size_t inEncDataSize, const std::vector<uint8_t>& inMac, std::vector<uint8_t>& meta, std::vector<uint8_t>& data)
{
	if (!inEncData)
	{
		throw RuntimeException("Null pointer is given to function DataSealer::detail::UnsealData.");
	}

	if (!consttime_memequal(inEncData, gsk_sgxSealedDataLabel, sizeof(gsk_sgxSealedDataLabel)))
	{
		throw RuntimeException("Invalid sealed data is given to function DataSealer::detail::UnsealData.");
	}

	const uint16_t key_policy = GetSgxKeyPolicyNum(keyPolicy);
	const sgx_attributes_t attribute_mask = { TSEAL_DEFAULT_FLAGSMASK /*flags*/, 0x0 /*xfrm*/ };
	const sgx_misc_select_t misc_mask = TSEAL_DEFAULT_MISCMASK;

	const uint8_t* sealedData = static_cast<const uint8_t*>(inEncData) + sizeof(gsk_sgxSealedDataLabel);
	const sgx_sealed_data_t& sealedDataRef = *reinterpret_cast<const sgx_sealed_data_t*>(sealedData);

	uint32_t pkgSize = sgx_get_encrypt_txt_len(&sealedDataRef);
	if (pkgSize == UINT32_MAX)
	{
		throw RuntimeException("Invalid sealed data is given to function DataSealer::detail::UnsealData.");
	}

	if (inMac.size() > 0)
	{
		//We want to verify the MAC first.
		if (inMac.size() != sizeof(sealedDataRef.aes_data.payload_tag) ||
			!consttime_memequal(inMac.data(), sealedDataRef.aes_data.payload_tag, inMac.size()))
		{
			throw RuntimeException("Invalid sealed data is given to function DataSealer::detail::UnsealData.");
		}
	}

	std::vector<uint8_t> pkg(pkgSize);
	sgx_status_t sgxRet = sgx_unseal_data(&sealedDataRef, nullptr, 0, pkg.data(), &pkgSize);
	if (sgxRet != SGX_SUCCESS)
	{
		throw RuntimeException(Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_unseal_data"));
	}
	if (pkgSize != sealedDataRef.aes_data.payload_size || pkgSize < (sizeof(uint32_t) + sizeof(uint32_t)))
	{
		throw RuntimeException("Invalid sealed data is given to function DataSealer::detail::UnsealData.");
	}

	std::vector<uint8_t>::iterator pkgIt = pkg.begin();
	uint32_t& pkgMetaSize = reinterpret_cast<uint32_t&>(*pkgIt);
	uint32_t& pkgDataSize = reinterpret_cast<uint32_t&>(*(pkgIt += sizeof(uint32_t)));
	if (sizeof(uint32_t) + sizeof(uint32_t) + pkgMetaSize + pkgDataSize > pkg.size())
	{
		throw RuntimeException("Invalid sealed data is given to function DataSealer::detail::UnsealData.");
	}
	std::vector<uint8_t>::iterator pkgMetaIt = (pkgIt += sizeof(uint32_t));
	std::vector<uint8_t>::iterator pkgDataIt = (pkgIt += pkgMetaSize);
	std::vector<uint8_t>::iterator pkgDataEndIt = (pkgIt += pkgDataSize);

	meta.reserve(pkgMetaSize);
	data.reserve(pkgDataSize);

	if (meta.size() > pkgMetaSize)
	{
		meta.resize(pkgMetaSize);
	}
	if (data.size() > pkgDataSize)
	{
		data.resize(pkgDataSize);
	}

	std::vector<uint8_t>::iterator pos;

	if (pkgMetaSize > 0 && meta.size() > 0)
	{
		pos = meta.begin() + 1;
	}
	else
	{
		pos = meta.end();
	}

	meta.insert(pos, pkgMetaIt, pkgDataIt);

	if (pkgDataSize > 0 && data.size() > 0)
	{
		pos = data.begin() + 1;
	}
	else
	{
		pos = data.end();
	}

	data.insert(pos, pkgDataIt, pkgDataEndIt);

	EXCEPTION_ASSERT(meta.size() == pkgMetaSize, "In function DataSealer::detail::UnsealData, the final metadata size is different from the sealed value.");
	EXCEPTION_ASSERT(data.size() == pkgDataSize, "In function DataSealer::detail::UnsealData, the final data size is different from the sealed value.");
}

#endif

//#endif //ENCLAVE_PLATFORM_SGX
