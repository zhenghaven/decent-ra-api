#pragma once
#ifndef SGX_RA_TOOLS_H
#define SGX_RA_TOOLS_H

#include <stdint.h>

#include <sgx_error.h>

typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef uint32_t sgx_ra_context_t;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

	sgx_status_t enclave_init_ra(const sgx_ec256_public_t *p_pub_key, int b_pse, sgx_ra_context_t *p_context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // !SGX_RA_TOOLS_H
