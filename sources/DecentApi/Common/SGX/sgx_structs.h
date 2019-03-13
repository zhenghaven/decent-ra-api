#pragma once

#ifndef DECENT_SGX_STRUCTS_H
#define DECENT_SGX_STRUCTS_H

#include <stdint.h>
#include <sgx_quote.h>
#include <sgx_tcrypto.h>

#include "../structs.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)

	typedef uint8_t ias_pse_hash_t[32];

	typedef struct _epid_pseudonym
	{
		uint8_t b[64];
		uint8_t k[64];
	} sgx_epid_pseudonym_t;

	typedef struct _sgx_timestamp_t
	{
		uint16_t m_year;
		uint8_t  m_month;
		uint8_t  m_day;

		uint8_t  m_hour;
		uint8_t  m_min;
		float  m_sec;
	} sgx_timestamp_t;

	typedef struct _sgx_ias_report_t
	{
		//uint8_t               m_id[16];        //Mandatory field. Probably a 128-bit UUID. But, not in use for now.
		sgx_timestamp_t         m_timestamp;     //Mandatory field (Parsed based on API) (chrono is not availble, couldn't find a better data type now).
		uint8_t                 m_version;       //Mandatory field (version of IAS, currently is only "3")
		uint8_t                 m_status;        //Mandatory field (enum ias_quote_status_t)
		uint8_t                 m_revoc_reason;  //Optional field (validated by m_status) (enum ias_revoc_reason_t)
		uint8_t                 m_pse_status;    //Optional field (validated by itself) (enum ias_pse_status_t)
		ias_pse_hash_t          m_pse_hash;      //Optional field (validated by m_pse_status)
		sgx_platform_info_t     m_info_blob;     //Optional field (validated by m_status & m_pse_status)
		uint8_t                 m_is_epid_pse_valid;
		sgx_epid_pseudonym_t    m_epidPseudonym; //Optional field (validated by m_is_epid_pse_valid)
		sgx_quote_t             m_quote;         //Mandatory field
	} sgx_ias_report_t;

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