#include "DataSealer.h"

#include <cmath>

#include "../../Common/Common.h"
#include "../../Common/RuntimeException.h"

#include "Crypto.h"

using namespace Decent;
using namespace Decent::Tools;

namespace
{
	//constexpr size_t gsk_sealedBlockSize = 4096; // block size is 4 KBytes.

	constexpr char   gsk_sealedDataLabel[] = "Decent_Data_Sealing";

	typedef uint8_t(IVType)[SUGGESTED_AESGCM_IV_SIZE];

	constexpr size_t gsk_knownAddSize = sizeof(IVType) + sizeof(uint64_t) + sizeof(uint64_t);

	constexpr size_t gsk_sealMetaSize = sizeof(gsk_sealedDataLabel) + sizeof(general_128bit_tag) + gsk_knownAddSize;

	constexpr size_t gsk_sealPkgAllKnownSize = gsk_sealMetaSize + sizeof(uint64_t) + sizeof(uint64_t);

	size_t GetTotalSealedBlockSize(const size_t inSealedBlockSize, const size_t inKeyMetaSize, const size_t inMetaSize, const size_t inDataSize, size_t& addSize, size_t& sealedSize)
	{
		const size_t totalDataSize = gsk_sealPkgAllKnownSize + inKeyMetaSize + inMetaSize + inDataSize;

		const size_t totalBlockNum = static_cast<size_t>(std::ceil(static_cast<float>(totalDataSize) / inSealedBlockSize));

		const size_t totalBlockSize = totalBlockNum * inSealedBlockSize;

		const size_t padSize = totalBlockSize - totalDataSize;

		sealedSize = sizeof(uint64_t) + sizeof(uint64_t) + inMetaSize + inDataSize + padSize;

		addSize = gsk_knownAddSize + inKeyMetaSize;

		//encOutSize = sgx_calc_sealed_data_size(0, encInSize);
		//if (encOutSize == UINT32_MAX)
		//{
		//	throw RuntimeException("Failed to calculate seal data size.");
		//}
		//metaSize = encOutSize - encInSize;

		//const size_t res = sizeof(gsk_sgxSealedDataLabel) + encOutSize;

		EXCEPTION_ASSERT(totalBlockSize == sizeof(gsk_sealedDataLabel) + sizeof(general_128bit_tag) + addSize + sealedSize, 
			"In function GetTotalSealedBlockSize, the calculation result is wrong.");

		return totalBlockSize;
	}
}

////////////////////////////
//Data Sealing:
////////////////////////////

//Structure:
// Metadata Label           (PlainText)         - 20  Bytes      -> 20   Bytes
// MAC                      (PlainText)         - 16  Bytes      -> 36   Bytes
// IV                       (PlainText) (MACed) - 12  Bytes      -> 48   Bytes
// Payload size             (PlainText) (MACed) - 8   Bytes      -> 56   Bytes
// Key Metadata Size        (PlainText) (MACed) - 8   Bytes      -> 64   Bytes
// Key Metadata             (PlainText) (MACed) - variable Size
// Additional Metadata size (Encrypted)         - 8   Bytes
// Data size                (Encrypted)         - 8   Bytes
// Additional Metadata      (Encrypted)         - variable Size
// Data                     (Encrypted)         - variable Size
// ----- Padding part 
// Padding bytes            (Encrypted)         - variable Size

std::vector<uint8_t> DataSealer::detail::SealData(KeyPolicy keyPolicy, const Ra::States & decentState, const std::string& keyLabel, 
	std::vector<uint8_t>& outMac, const void * inMeta, const size_t inMetaSize, const void * inData, const size_t inDataSize, const size_t sealedBlockSize)
{
	std::vector<uint8_t> keyMeta = GenSealKeyRecoverMeta(false);
	General128BitKey sealKey;
	DeriveSealKey(keyPolicy, decentState, keyLabel, sealKey, keyMeta, std::vector<uint8_t>());

	size_t addSize = 0;
	size_t sealedSize = 0;
	std::vector<uint8_t> sealedRes(
		GetTotalSealedBlockSize(sealedBlockSize, keyMeta.size(), inMetaSize, inDataSize, addSize, sealedSize));

	uint8_t* sealedResPtr = sealedRes.data();

	//Construct plain text input package:
	std::vector<uint8_t> inputPkg(sealedSize, 0);

	uint8_t* inputPkgPtr = inputPkg.data();
	uint64_t& inputPkgMetaSize = *reinterpret_cast<uint64_t*>(inputPkgPtr);
	uint64_t& inputPkgDataSize = *reinterpret_cast<uint64_t*>(inputPkgPtr += sizeof(uint64_t));
	uint8_t* inputPkgMeta = (inputPkgPtr += sizeof(uint64_t));
	uint8_t* inputPkgData = (inputPkgPtr += inMetaSize);

	inputPkgMetaSize = inMetaSize;
	inputPkgDataSize = inDataSize;
	std::memcpy(inputPkgMeta, inMeta, inMetaSize);
	std::memcpy(inputPkgData, inData, inDataSize);

	//Construct output package:
	//    Metadata Label:
	std::memcpy(&sealedRes[0], gsk_sealedDataLabel, sizeof(gsk_sealedDataLabel));

	uint8_t* sealedResMacPtr = (sealedResPtr += sizeof(gsk_sealedDataLabel));

	//    MACed part:
	uint8_t* sealedResIvPtr = (sealedResPtr += sizeof(general_128bit_tag));
	uint64_t& sealedResPayloadSize = *reinterpret_cast<uint64_t*>(sealedResPtr += sizeof(IVType));
	uint64_t& sealedResKeyMetaSize = *reinterpret_cast<uint64_t*>(sealedResPtr += sizeof(uint64_t));
	uint8_t* sealedResKeyMetaPtr = sealedResPtr += sizeof(uint64_t);

	//    Sealed Part:
	uint8_t* sealedResOutputPtr = (sealedResPtr += keyMeta.size());

	EXCEPTION_ASSERT((&sealedRes[sealedRes.size() - 1] - sealedResOutputPtr + 1) == inputPkg.size(), 
		"In function DataSealer::detail::SealData, the free space in the sealed result does not match the size of input package.")

	SecureRand(sealedResIvPtr, sizeof(IVType));
	sealedResPayloadSize = sealedSize;
	sealedResKeyMetaSize = keyMeta.size();
	std::copy(keyMeta.begin(), keyMeta.end(), sealedResKeyMetaPtr);
		
	PlatformAesGcmEncrypt(sealKey.data(), sealKey.size(),
		inputPkg.data(), inputPkg.size(), sealedResOutputPtr,
		sealedResIvPtr, sizeof(IVType),
		sealedResIvPtr, addSize,
		sealedResMacPtr, sizeof(general_128bit_tag));

	return sealedRes;
}

void DataSealer::detail::UnsealData(KeyPolicy keyPolicy, const Ra::States & decentState, const std::string & keyLabel, 
	const void * inEncData, const size_t inEncDataSize, const std::vector<uint8_t>& inMac, std::vector<uint8_t>& outMeta, std::vector<uint8_t>& outData, const size_t sealedBlockSize)
{
	if (!inEncData)
	{
		throw RuntimeException("Null pointer is given to function DataSealer::detail::UnsealData.");
	}

	if (inEncDataSize < sealedBlockSize ||
		!consttime_memequal(inEncData, gsk_sealedDataLabel, sizeof(gsk_sealedDataLabel)))
	{
		throw RuntimeException("Invalid sealed data is given to function DataSealer::detail::UnsealData.");
	}

	//Sealed package:
	const uint8_t* sealedPkgPtr = static_cast<const uint8_t*>(inEncData);
	
	//    MAC:
	const uint8_t* sealedMacPtr = (sealedPkgPtr += sizeof(gsk_sealedDataLabel));

	//    MACed part:
	const uint8_t* sealedIvPtr = (sealedPkgPtr += sizeof(general_128bit_tag));
	const uint64_t& sealedPayloadSize = *reinterpret_cast<const uint64_t*>(sealedPkgPtr += sizeof(IVType));
	const uint64_t& sealedKeyMetaSize = *reinterpret_cast<const uint64_t*>(sealedPkgPtr += sizeof(uint64_t));
	const uint8_t* sealedKeyMetaPtr = sealedPkgPtr += sizeof(uint64_t);

	//    Sealed Part:
	const uint8_t* sealedOutputPtr = (sealedPkgPtr += sealedKeyMetaSize);

	const size_t allMetaSize = sealedOutputPtr - static_cast<const uint8_t*>(inEncData);
	if (sealedPayloadSize < (sizeof(uint64_t) + sizeof(uint64_t)) ||
		(inEncDataSize - allMetaSize) != sealedPayloadSize)
	{
		throw RuntimeException("Sealed data with invalid size is given to function DataSealer::detail::UnsealData.");
	}

	if (inMac.size() > 0)
	{
		//We want to verify the MAC first.
		if (inMac.size() != sizeof(general_128bit_tag) ||
			!consttime_memequal(inMac.data(), sealedMacPtr, inMac.size()))
		{
			throw RuntimeException("Invalid sealed data is given to function DataSealer::detail::UnsealData.");
		}
	}

	std::vector<uint8_t> unsealedPkg(sealedPayloadSize);

	General128BitKey sealKey;
	DeriveSealKey(keyPolicy, decentState, keyLabel, sealKey.data(), sealKey.size(), sealedKeyMetaPtr, sealedKeyMetaSize, std::vector<uint8_t>());

	PlatformAesGcmDecrypt(sealKey.data(), sealKey.size(),
		sealedOutputPtr, sealedPayloadSize, unsealedPkg.data(),
		sealedIvPtr, sizeof(IVType),
		sealedIvPtr, gsk_knownAddSize + sealedKeyMetaSize,
		sealedMacPtr, sizeof(general_128bit_tag));

	std::vector<uint8_t>::iterator pkgIt = unsealedPkg.begin();
	uint64_t& pkgMetaSize = reinterpret_cast<uint64_t&>(*pkgIt);
	uint64_t& pkgDataSize = reinterpret_cast<uint64_t&>(*(pkgIt += sizeof(uint64_t)));
	if (sizeof(uint64_t) + sizeof(uint64_t) + pkgMetaSize + pkgDataSize > unsealedPkg.size())
	{
		throw RuntimeException("Invalid sealed data is given to function DataSealer::detail::UnsealData.");
	}
	std::vector<uint8_t>::iterator pkgMetaIt = (pkgIt += sizeof(uint64_t));
	std::vector<uint8_t>::iterator pkgDataIt = (pkgIt += pkgMetaSize);
	std::vector<uint8_t>::iterator pkgDataEndIt = (pkgIt += pkgDataSize);

	outMeta.reserve(pkgMetaSize);
	outData.reserve(pkgDataSize);

	if (outMeta.size() > pkgMetaSize)
	{
		outMeta.resize(pkgMetaSize);
	}
	if (outData.size() > pkgDataSize)
	{
		outData.resize(pkgDataSize);
	}

	std::vector<uint8_t>::iterator pos;

	if (pkgMetaSize > 0 && outMeta.size() > 0)
	{
		pos = outMeta.begin() + 1;
	}
	else
	{
		pos = outMeta.end();
	}

	outMeta.insert(pos, pkgMetaIt, pkgDataIt);

	if (pkgDataSize > 0 && outData.size() > 0)
	{
		pos = outData.begin() + 1;
	}
	else
	{
		pos = outData.end();
	}

	outData.insert(pos, pkgDataIt, pkgDataEndIt);

	EXCEPTION_ASSERT(outMeta.size() == pkgMetaSize, "In function DataSealer::detail::UnsealData, the final metadata size is different from the sealed value.");
	EXCEPTION_ASSERT(outData.size() == pkgDataSize, "In function DataSealer::detail::UnsealData, the final data size is different from the sealed value.");
}

