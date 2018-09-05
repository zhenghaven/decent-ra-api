#pragma once

#ifndef IAS_REPORT_H
#define IAS_REPORT_H

#include <stdint.h>
#include <sgx_quote.h>
#include <sgx_error.h>

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

	typedef struct _ias_report_t
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

#pragma pack(pop)
	
	sgx_status_t parse_ias_report(sgx_ias_report_t* out_report, const char* in_str);

#ifdef __cplusplus
}
#endif

#endif //IAS_REPORT_H
