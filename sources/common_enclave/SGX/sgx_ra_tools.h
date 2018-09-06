#pragma once

#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL

#ifndef SGX_RA_TOOLS_H
#define SGX_RA_TOOLS_H

#include <stdint.h>

#include <sgx_error.h>
#include <sgx_tkey_exchange.h>

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !SGX_RA_TOOLS_H

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL
