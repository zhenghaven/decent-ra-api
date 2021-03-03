#pragma once

#include <array>
#include <string>

#include <mbedTLScpp/Cmac.hpp>
#include <mbedTLScpp/SKey.hpp>

namespace Decent
{
	namespace Sgx
	{
		/**
		 * \brief  Cipher-based Key Derivation Function (CKDF). Based on the the key
		 *         derivation function used in SGX RA.
		 *
		 * \tparam _cipherType       Type of the cipher.
		 * \tparam _reqKeySizeInBits Size of requested key. In bits.
		 * \tparam _cipherMode       Mode of the cipher.
		 *
		 * \param inKey The input key.
		 * \param label The label.
		 *
		 * \return The output key.
		 */
		template<mbedTLScpp::CipherType _cipherType,
			uint16_t                    _reqKeySizeInBits,
			mbedTLScpp::CipherMode      _cipherMode,
			typename                    _KeyCtnType>
		inline mbedTLScpp::SKey<_reqKeySizeInBits>
			Ckdf(
				const mbedTLScpp::ContCtnReadOnlyRef<_KeyCtnType, true>& inKey,
				const std::string& label)
		{
			using namespace mbedTLScpp;

			static constexpr std::array<uint8_t, 1> counter{0x01};
			static constexpr std::array<uint8_t, 1> nullTerm{0x00};
			static constexpr std::array<uint16_t, 1> keyBitSize{ _reqKeySizeInBits };

			SKey<_reqKeySizeInBits> cmacKey;
			SKey<_reqKeySizeInBits> deriveKey;

			//mbedTLScpp::Cmacer<_cipherType, _reqKeySizeInBits, _cipherMode>(cmacKey).Calc(deriveKey.m_key, inKey.m_key);
			Cmacer<_cipherType, _reqKeySizeInBits, _cipherMode> macer1(CtnFullR(cmacKey));
			MBEDTLSCPP_MAKE_C_FUNC_CALL(Decent::Sgx::Ckdf, mbedtls_cipher_cmac_update,
				macer1.Get(),
				inKey.BeginBytePtr(), inKey.GetRegionSize()
			);
			MBEDTLSCPP_MAKE_C_FUNC_CALL(Decent::Sgx::Ckdf, mbedtls_cipher_cmac_finish,
				macer1.Get(),
				static_cast<unsigned char*>(deriveKey.data())
			);


			//CMACer<cType, cSize, cMode>(deriveKey).Calc(outKey.m_key,
			//	counter,     //Counter
			//	label,       //Label
			//	nullTerm,    //Null terminator?
			//	keyBitSize); //Bit length of the output key

			SKey<_reqKeySizeInBits> resKey;

			Cmacer<_cipherType, _reqKeySizeInBits, _cipherMode> macer2(CtnFullR(deriveKey));
			MBEDTLSCPP_MAKE_C_FUNC_CALL(Decent::Sgx::Ckdf, mbedtls_cipher_cmac_update,
				macer2.Get(),
				counter.data(), counter.size()
			);
			auto labelRef = CtnFullR(label);
			MBEDTLSCPP_MAKE_C_FUNC_CALL(Decent::Sgx::Ckdf, mbedtls_cipher_cmac_update,
				macer2.Get(),
				labelRef.BeginBytePtr(), labelRef.GetRegionSize()
			);
			MBEDTLSCPP_MAKE_C_FUNC_CALL(Decent::Sgx::Ckdf, mbedtls_cipher_cmac_update,
				macer2.Get(),
				nullTerm.data(), nullTerm.size()
			);
			auto keyBitSizeRef = CtnFullR(keyBitSize);
			MBEDTLSCPP_MAKE_C_FUNC_CALL(Decent::Sgx::Ckdf, mbedtls_cipher_cmac_update,
				macer2.Get(),
				keyBitSizeRef.BeginBytePtr(), keyBitSizeRef.GetRegionSize()
			);
			MBEDTLSCPP_MAKE_C_FUNC_CALL(Decent::Sgx::Ckdf, mbedtls_cipher_cmac_finish,
				macer2.Get(),
				static_cast<unsigned char*>(resKey.data())
			);

			return resKey;
		}
	}
}
