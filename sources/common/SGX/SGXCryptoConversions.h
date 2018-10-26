#pragma once

#include "../GeneralKeyTypes.h"

typedef struct _sgx_ec256_private_t sgx_ec256_private_t;
typedef struct _sgx_ec256_public_t sgx_ec256_public_t;
typedef struct _sgx_ec256_dh_shared_t sgx_ec256_dh_shared_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;
typedef void* sgx_ecc_state_handle_t;

inline const general_secp256r1_public_t* SgxEc256Type2General(const sgx_ec256_public_t* x)
{
	return reinterpret_cast<const general_secp256r1_public_t*>(x);
}

inline const general_secp256r1_private_t* SgxEc256Type2General(const sgx_ec256_private_t* x)
{
	return reinterpret_cast<const general_secp256r1_private_t*>(x);
}

inline const general_secp256r1_shared_t* SgxEc256Type2General(const sgx_ec256_dh_shared_t* x)
{
	return reinterpret_cast<const general_secp256r1_shared_t*>(x);
}

inline const general_secp256r1_signature_t* SgxEc256Type2General(const sgx_ec256_signature_t* x)
{
	return reinterpret_cast<const general_secp256r1_signature_t*>(x);
}

inline general_secp256r1_public_t* SgxEc256Type2General(sgx_ec256_public_t* x)
{
	return reinterpret_cast<general_secp256r1_public_t*>(x);
}

inline general_secp256r1_private_t* SgxEc256Type2General(sgx_ec256_private_t* x)
{
	return reinterpret_cast<general_secp256r1_private_t*>(x);
}

inline general_secp256r1_shared_t* SgxEc256Type2General(sgx_ec256_dh_shared_t* x)
{
	return reinterpret_cast<general_secp256r1_shared_t*>(x);
}

inline general_secp256r1_signature_t* SgxEc256Type2General(sgx_ec256_signature_t* x)
{
	return reinterpret_cast<general_secp256r1_signature_t*>(x);
}

inline const general_secp256r1_public_t& SgxEc256Type2General(const sgx_ec256_public_t& x)
{
	return reinterpret_cast<const general_secp256r1_public_t&>(x);
}

inline const general_secp256r1_private_t& SgxEc256Type2General(const sgx_ec256_private_t& x)
{
	return reinterpret_cast<const general_secp256r1_private_t&>(x);
}

inline const general_secp256r1_shared_t& SgxEc256Type2General(const sgx_ec256_dh_shared_t& x)
{
	return reinterpret_cast<const general_secp256r1_shared_t&>(x);
}

inline const general_secp256r1_signature_t& SgxEc256Type2General(const sgx_ec256_signature_t& x)
{
	return reinterpret_cast<const general_secp256r1_signature_t&>(x);
}

inline general_secp256r1_public_t& SgxEc256Type2General(sgx_ec256_public_t& x)
{
	return reinterpret_cast<general_secp256r1_public_t&>(x);
}

inline general_secp256r1_private_t& SgxEc256Type2General(sgx_ec256_private_t& x)
{
	return reinterpret_cast<general_secp256r1_private_t&>(x);
}

inline general_secp256r1_shared_t& SgxEc256Type2General(sgx_ec256_dh_shared_t& x)
{
	return reinterpret_cast<general_secp256r1_shared_t&>(x);
}

inline general_secp256r1_signature_t& SgxEc256Type2General(sgx_ec256_signature_t& x)
{
	return reinterpret_cast<general_secp256r1_signature_t&>(x);
}

inline const sgx_ec256_public_t* GeneralEc256Type2Sgx(const general_secp256r1_public_t* x)
{
	return reinterpret_cast<const sgx_ec256_public_t*>(x);
}

inline const sgx_ec256_private_t* GeneralEc256Type2Sgx(const general_secp256r1_private_t* x)
{
	return reinterpret_cast<const sgx_ec256_private_t*>(x);
}

inline const sgx_ec256_dh_shared_t* GeneralEc256Type2Sgx(const general_secp256r1_shared_t* x)
{
	return reinterpret_cast<const sgx_ec256_dh_shared_t*>(x);
}

inline const sgx_ec256_signature_t* GeneralEc256Type2Sgx(const general_secp256r1_signature_t* x)
{
	return reinterpret_cast<const sgx_ec256_signature_t*>(x);
}

inline sgx_ec256_public_t* GeneralEc256Type2Sgx(general_secp256r1_public_t* x)
{
	return reinterpret_cast<sgx_ec256_public_t*>(x);
}

inline sgx_ec256_private_t* GeneralEc256Type2Sgx(general_secp256r1_private_t* x)
{
	return reinterpret_cast<sgx_ec256_private_t*>(x);
}

inline sgx_ec256_dh_shared_t* GeneralEc256Type2Sgx(general_secp256r1_shared_t* x)
{
	return reinterpret_cast<sgx_ec256_dh_shared_t*>(x);
}

inline sgx_ec256_signature_t* GeneralEc256Type2Sgx(general_secp256r1_signature_t* x)
{
	return reinterpret_cast<sgx_ec256_signature_t*>(x);
}

inline const sgx_ec256_public_t& GeneralEc256Type2Sgx(const general_secp256r1_public_t& x)
{
	return reinterpret_cast<const sgx_ec256_public_t&>(x);
}

inline const sgx_ec256_private_t& GeneralEc256Type2Sgx(const general_secp256r1_private_t& x)
{
	return reinterpret_cast<const sgx_ec256_private_t&>(x);
}

inline const sgx_ec256_dh_shared_t& GeneralEc256Type2Sgx(const general_secp256r1_shared_t& x)
{
	return reinterpret_cast<const sgx_ec256_dh_shared_t&>(x);
}

inline const sgx_ec256_signature_t& GeneralEc256Type2Sgx(const general_secp256r1_signature_t& x)
{
	return reinterpret_cast<const sgx_ec256_signature_t&>(x);
}

inline sgx_ec256_public_t& GeneralEc256Type2Sgx(general_secp256r1_public_t& x)
{
	return reinterpret_cast<sgx_ec256_public_t&>(x);
}

inline sgx_ec256_private_t& GeneralEc256Type2Sgx(general_secp256r1_private_t& x)
{
	return reinterpret_cast<sgx_ec256_private_t&>(x);
}

inline sgx_ec256_dh_shared_t& GeneralEc256Type2Sgx(general_secp256r1_shared_t& x)
{
	return reinterpret_cast<sgx_ec256_dh_shared_t&>(x);
}

inline sgx_ec256_signature_t& GeneralEc256Type2Sgx(general_secp256r1_signature_t& x)
{
	return reinterpret_cast<sgx_ec256_signature_t&>(x);
}

