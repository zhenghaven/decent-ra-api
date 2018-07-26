#pragma once

#ifndef SGX_RA_MSG4_H
#define SGX_RA_MSG4_H

//#include <sgx_key_exchange.h>

//NOTE: These come from Intel SGX SDK RA sample code.

typedef enum {
	IAS_QUOTE_OK,
	IAS_QUOTE_SIGNATURE_INVALID,
	IAS_QUOTE_GROUP_REVOKED,
	IAS_QUOTE_SIGNATURE_REVOKED,
	IAS_QUOTE_KEY_REVOKED,
	IAS_QUOTE_SIGRL_VERSION_MISMATCH,
	IAS_QUOTE_GROUP_OUT_OF_DATE,
} ias_quote_status_t;

// Revocation Reasons from RFC5280
typedef enum {
	IAS_REVOC_REASON_NONE,
	IAS_REVOC_REASON_KEY_COMPROMISE,
	IAS_REVOC_REASON_CA_COMPROMISED,
	IAS_REVOC_REASON_SUPERCEDED,
	IAS_REVOC_REASON_CESSATION_OF_OPERATION,
	IAS_REVOC_REASON_CERTIFICATE_HOLD,
	IAS_REVOC_REASON_PRIVILEGE_WITHDRAWN,
	IAS_REVOC_REASON_AA_COMPROMISE,
} ias_revoc_reason_t;

typedef enum {
	IAS_PSE_OK,
	IAS_PSE_DESC_TYPE_NOT_SUPPORTED,
	IAS_PSE_ISVSVN_OUT_OF_DATE,
	IAS_PSE_MISCSELECT_INVALID,
	IAS_PSE_ATTRIBUTES_INVALID,
	IAS_PSE_MRSIGNER_INVALID,
	IAS_PS_HW_GID_REVOKED,
	IAS_PS_HW_PRIVKEY_RLVER_MISMATCH,
	IAS_PS_HW_SIG_RLVER_MISMATCH,
	IAS_PS_HW_CA_ID_INVALID,
	IAS_PS_HW_SEC_INFO_INVALID,
	IAS_PS_HW_PSDA_SVN_OUT_OF_DATE,
} ias_pse_status_t;

#define SAMPLE_PLATFORM_INFO_SIZE 101
typedef struct _ias_platform_info_blob_t
{
	uint8_t platform_info[SAMPLE_PLATFORM_INFO_SIZE];
} ias_platform_info_blob_t;

typedef struct _ra_msg4_t
{
	uint32_t                id;
	ias_quote_status_t      status;
	uint32_t                revocation_reason;
	ias_platform_info_blob_t    info_blob;
	ias_pse_status_t        pse_status;
} sgx_ra_msg4_t;

#endif //SGX_RA_MSG4_H