#pragma once
#ifndef SGX_RA_TOOLS_H
#define SGX_RA_TOOLS_H

#include <stdint.h>

#include <sgx_error.h>

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ec256_private_t sgx_ec256_private_t; 
typedef struct _sgx_ec256_dh_shared_t sgx_ec256_dh_shared_t;
#define SGX_CMAC_KEY_SIZE               16
typedef uint8_t sgx_ec_key_128bit_t[SGX_CMAC_KEY_SIZE];
typedef uint32_t sgx_ra_context_t;

typedef sgx_status_t(*sgx_ra_derive_secret_keys_t)(
	const sgx_ec256_dh_shared_t* p_shared_key,
	uint16_t kdf_id,
	sgx_ec_key_128bit_t* p_smk_key,
	sgx_ec_key_128bit_t* p_sk_key,
	sgx_ec_key_128bit_t* p_mk_key,
	sgx_ec_key_128bit_t* p_vk_key);

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

	/**
	* \brief	RA session initialization. This is a wrapper function for decent_ra_init_ex.
	*           p_a and p_g_a can be NULL (Both are NULL, or both are not NULL). if they are null, decent_ra_get_ga should be used in sgx_ra_get_msg1.
	*           Otherwise, use decent_ra_get_ga_only in sgx_ra_get_msg1.
	*
	* \param	p_pub_key      [in]  The public encryption key from serivce provider.
	* \param	b_pse          [in]  A boolean value enables PSE.
	* \param	p_a            [in]  The private encryption key of client side (this key must be held by enclave only). This can be NULL so that a random key pair will be generated.
	* \param	p_g_a          [in]  The public encryption key of client side (this key must be corresponding to p_a). This can be NULL so that a random key pair will be generated.
	* \param	derive_key_cb  [in]  A function pointer. Please referes to sgx_ra_derive_secret_keys_t in sgx_tkey_exchange.h
	* \param	p_context      [out] Output of context ID.
	*
	* \return	SGX_SUCCESS for success, otherwise please refers to sgx_error.h .
	*/
	sgx_status_t enclave_init_ra(const sgx_ec256_public_t *p_pub_key, int b_pse, const sgx_ec256_private_t *p_a, const sgx_ec256_public_t *p_g_a, sgx_ra_derive_secret_keys_t derive_key_cb, sgx_ra_context_t *p_context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !SGX_RA_TOOLS_H
