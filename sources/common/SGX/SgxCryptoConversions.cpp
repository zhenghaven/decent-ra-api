#include <cstddef>

#include <sgx_tcrypto.h>
#include "../general_key_types.h"

//In newer version of gcc, the definition of offsetof in SGX SDK is not acceptable.
#ifdef ENCLAVE_ENVIRONMENT
#ifdef __GNUC__
#define myoffsetof(s,m) __builtin_offsetof(s,m)
#elif defined(__cplusplus)
#define myoffsetof(s,m) ((::size_t)&reinterpret_cast<char const volatile&>((((s*)0)->m)))
#else
#define myoffsetof(s,m) ((size_t)&(((s*)0)->m))
#endif
#endif // ENCLAVE_ENVIRONMENT


#define SGX_GENERAL_KEY_TYPE_ERROR_MSG "The key type of SGX is incompatible with the general key type!"

static_assert(sizeof(sgx_ec256_private_t) == sizeof(general_secp256r1_private_t), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(sizeof(sgx_ec256_public_t) == sizeof(general_secp256r1_public_t), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(sizeof(sgx_ec256_dh_shared_t) == sizeof(general_secp256r1_shared_t), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(sizeof(sgx_ec256_signature_t) == sizeof(general_secp256r1_signature_t), SGX_GENERAL_KEY_TYPE_ERROR_MSG);

static_assert(offsetof(sgx_ec256_private_t, r) == offsetof(general_secp256r1_private_t, r), SGX_GENERAL_KEY_TYPE_ERROR_MSG);

static_assert(offsetof(sgx_ec256_public_t, gx) == offsetof(general_secp256r1_public_t, x), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(offsetof(sgx_ec256_public_t, gy) == offsetof(general_secp256r1_public_t, y), SGX_GENERAL_KEY_TYPE_ERROR_MSG);

static_assert(offsetof(sgx_ec256_dh_shared_t, s) == offsetof(sgx_ec256_dh_shared_t, s), SGX_GENERAL_KEY_TYPE_ERROR_MSG);

static_assert(offsetof(sgx_ec256_signature_t, x) == offsetof(general_secp256r1_signature_t, x), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
static_assert(offsetof(sgx_ec256_signature_t, y) == offsetof(general_secp256r1_signature_t, y), SGX_GENERAL_KEY_TYPE_ERROR_MSG);
