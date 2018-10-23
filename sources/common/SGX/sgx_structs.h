#pragma once

#ifndef DECENT_SGX_STRUCTS_H
#define DECENT_SGX_STRUCTS_H

#include <stdint.h>
#include <sgx_quote.h>
#include <sgx_tcrypto.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

#define SGX_QUOTE_UNLINKABLE_SIGNATURE 0
#define SGX_QUOTE_LINKABLE_SIGNATURE   1

//Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion
#define SGX_DEFAULT_AES_CMAC_KDF_ID    0x0001
#define IAS_REQUEST_NONCE_SIZE         32

	typedef uint8_t ias_pse_hash_t[32];

	typedef struct _epid_pseudonym
	{
		uint8_t b[64];
		uint8_t k[64];
	} sgx_epid_pseudonym_t;

	typedef struct _sgx_ias_report_t
	{
		//number                m_id;            //Don't know the size yet.
		//string                m_timestamp;     //Don't use it now.
		uint8_t                 m_status;        //Mandatory field (enum ias_quote_status_t)
		uint8_t                 m_revoc_reason;  //Optional field (validated by m_status) (enum ias_revoc_reason_t)
		uint8_t                 m_pse_status;    //Optional field (validated by itself) (enum ias_pse_status_t)
		ias_pse_hash_t          m_pse_hash;      //Optional field (validated by m_pse_status)
		uint8_t                 m_is_info_blob_valid;
		sgx_platform_info_t     m_info_blob;     //Optional field (validated by m_is_info_blob_valid)
		uint8_t                 m_is_epid_pse_valid;
		sgx_epid_pseudonym_t    m_epidPseudonym; //Optional field (validated by m_is_epid_pse_valid)
		sgx_quote_t             m_quote;         //Mandatory field
	} sgx_ias_report_t;

	typedef struct _sgx_ra_config
	{
		uint8_t   linkable_sign;  //On(1) or Off(0)
		uint16_t  ckdf_id;
		uint8_t   enable_pse;     //Enabled(1) or Disabled(0)
		uint8_t   allow_ofd_enc;  //Allow(1) or Disallow(0) out-of-date enclave.
		uint8_t   allow_ofd_pse;  //Allow(1) or Disallow(0) out-of-date PSE.
	} sgx_ra_config;

	typedef struct _sgx_ra_msg0s_t
	{
		uint32_t  extended_grp_id;
	} sgx_ra_msg0s_t;

	typedef struct _sgx_ra_msg0r_t
	{
		sgx_ra_config       ra_config;
		sgx_ec256_public_t  sp_pub_key;
	} sgx_ra_msg0r_t;

	typedef struct _sgx_ra_msg4_t
	{
		sgx_ec256_signature_t  signature;
		uint8_t                is_accepted;  //Yes(1) or No(0)
		sgx_ias_report_t       report;
	} sgx_ra_msg4_t;
#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#endif //!DECENT_SGX_STRUCTS_H