#pragma once

#ifndef DECENT_STRUCTS_H
#define DECENT_STRUCTS_H

#include <stdint.h>

#define SGX_QUOTE_UNLINKABLE_SIGNATURE 0
#define SGX_QUOTE_LINKABLE_SIGNATURE   1

//Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion
#define SGX_DEFAULT_AES_CMAC_KDF_ID    0x0001
#define IAS_REQUEST_NONCE_SIZE         32

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push, 1)

	typedef struct _sgx_ra_config
	{
		uint8_t   linkable_sign;   //On(1) or Off(0)
		uint16_t  ckdf_id;
		uint8_t   enable_pse;      //Enabled(1) or Disabled(0)
		uint8_t   allow_ofd_enc;   //Allow(1) or Disallow(0) out-of-date enclave.
		uint8_t   allow_cfgn_enc;  //Allow(1) or Disallow(0) configuration needed enclave.
		uint8_t   allow_ofd_pse;   //Allow(1) or Disallow(0) out-of-date PSE.
	} sgx_ra_config;

	typedef struct _report_timestamp_t
	{
		uint16_t m_year;
		uint8_t  m_month;
		uint8_t  m_day;

		uint32_t  m_sec;
		uint32_t m_nanoSec;
	} report_timestamp_t;

#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif //!DECENT_STRUCTS_H
