#pragma once

#include "../../Common/GeneralKeyTypes.h"

typedef struct _report_t sgx_report_t;

namespace Decent
{
	namespace Tools
	{

		enum class KeyType
		{
			EInitToken,
			Provision,
			ProvisionSeal,
			Report,
			Seal,
		};

		enum class KeyPolicy
		{
			ByMrEnclave,
			ByMrSigner,
			ByMrEnclaveAndMrSigner,
		};

		struct KeyRecoverMeta
		{
			uint8_t m_keyId[32];  //256-bit
			uint8_t m_CpuSvn[16]; //128-bit
			uint16_t m_IsvSvn; //16-bit
		};

		namespace detail
		{
			void DeriveKey(KeyType keyType, KeyPolicy keyPolicy, general_128bit_key& outKey, const KeyRecoverMeta& meta);

			//void DeriveKey(KeyType keyType, KeyPolicy keyPolicy, const std::string& label, void* outKey, size_t outKeySize, const KeyRecoverMeta& meta);
		}

		void DeriveKey(KeyType keyType, KeyPolicy keyPolicy, const std::string& label, General128BitKey outKey, const KeyRecoverMeta& meta);

		/**
		 * \brief	Generates a new key recover meta data.
		 *
		 * \exception	Decent::RuntimeException	This is thrown if it failed to generate the report or
		 * 											key ID.
		 *
		 * \param [in,out]	outMeta   	The newly generated meta output.
		 * \param 		  	isGenKeyId	(Optional) True if is needed to generate key ID, false if not.
		 */
		void GenNewKeyRecoverMeta(KeyRecoverMeta& outMeta, bool isGenKeyId = true);

		/**
		 * \brief	SGX get self report. There is only one static copy of this report, which is generated
		 * 			once this function is called.
		 *
		 * \exception	Decent::RuntimeException	This is thrown if it failed to generate the report.
		 *
		 * \return	A reference to a const sgx_report_t.
		 */
		const sgx_report_t& SgxGetSelfReport();
	}
}
