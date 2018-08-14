#pragma once
#ifndef SGX_RA_TOOLS_H
#define SGX_RA_TOOLS_H

#include <stdint.h>

#include <sgx_error.h>
#include "decent_tkey_exchange.h"

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ec256_private_t sgx_ec256_private_t; 
typedef struct _sgx_ec256_dh_shared_t sgx_ec256_dh_shared_t;
#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];
typedef uint32_t sgx_ra_context_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

	/**
	* \brief	RA session initialization. This is a wrapper function for sgx_ra_init_ex.
	*
	* \param	p_pub_key      [in]  The public encryption key from serivce provider.
	* \param	b_pse          [in]  A boolean value enables PSE.
	* \param	derive_key_cb  [in]  A function pointer. Can be nullptr. Please referes to sgx_ra_derive_secret_keys_t in sgx_tkey_exchange.h
	* \param	p_context      [out] Output of context ID.
	*
	* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h .
	*/
	sgx_status_t enclave_init_sgx_ra(const sgx_ec256_public_t *p_pub_key, int b_pse, sgx_ra_derive_secret_keys_t derive_key_cb, sgx_ra_context_t *p_context);

	/**
	* \brief	RA session initialization. This is a wrapper function for decent_ra_init_ex.
	*
	* \param	p_pub_key      [in]  The public encryption key from serivce provider.
	* \param	b_pse          [in]  A boolean value enables PSE.
	* \param	func           [in]  A lambda function that generate report data .
	* \param	derive_key_cb  [in]  A function pointer. Please referes to sgx_ra_derive_secret_keys_t in sgx_tkey_exchange.h
	* \param	p_context      [out] Output of context ID.
	*
	* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h .
	*/
	sgx_status_t enclave_init_decent_ra(const sgx_ec256_public_t *p_pub_key, int b_pse, ReportDataGenerator func, sgx_ra_derive_secret_keys_t derive_key_cb, sgx_ra_context_t *p_context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !SGX_RA_TOOLS_H
