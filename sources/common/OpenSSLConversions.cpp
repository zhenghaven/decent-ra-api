#include "OpenSSLConversions.h"

#include <vector>
#include <cstdint>
#include <iterator>
#include <algorithm>

#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#define C_TRUE 1
#define C_FALSE 0

#ifdef ENCLAVE_CODE

namespace std
{
	template<class T, size_t Size>
	inline reverse_iterator<T *> rbegin(T(&_Array)[Size])
	{	// get beginning of reversed array
		return (reverse_iterator<T *>(_Array + Size));
	}

	template<class T, size_t Size>
	inline reverse_iterator<T *> rend(T(&_Array)[Size])
	{	// get end of reversed array
		return (reverse_iterator<T *>(_Array));
	}
}

#endif // ENCLAVE_CODE

struct DecentEccContext
{
	EC_GROUP* m_grp;
	BN_CTX* m_bnCtx;

	DecentEccContext() :
		m_grp(EC_GROUP_new_by_curve_name(ECC256_CURVE_NAME)),
		m_bnCtx(BN_CTX_new())
	{}

	~DecentEccContext()
	{
		EC_GROUP_free(m_grp);
		BN_CTX_free(m_bnCtx);
	}
};

int ECKeyOpenContext(ecc_state_handle_t * ctxPtr)
{
	if (ctxPtr == nullptr)
	{
		return C_FALSE;
	}

	DecentEccContext* ctx = new DecentEccContext;
	if (ctx->m_grp == nullptr ||
		ctx->m_bnCtx == nullptr)
	{
		delete ctx;
		return C_FALSE;
	}

	*ctxPtr = ctx;
	return C_TRUE;
}

void ECKeyCloseContext(ecc_state_handle_t inCtx)
{
	if (inCtx == nullptr)
	{
		return;
	}

	DecentEccContext* ctx = reinterpret_cast<DecentEccContext*>(inCtx);
	delete ctx;
}

static DecentEccContext* OpenTempContext()
{
	ecc_state_handle_t tmpPtr = nullptr;
	if (!ECKeyOpenContext(&tmpPtr))
	{
		return nullptr;
	}

	return reinterpret_cast<DecentEccContext*>(tmpPtr);
}

static inline void CloseTempContext(ecc_state_handle_t inCtx, DecentEccContext* eccCtx)
{
	if (inCtx == nullptr)
	{
		ECKeyCloseContext(eccCtx);
	}
}

int ECKeyPrvOpenSSL2General(const BIGNUM *inPrv, general_secp256r1_private_t *outPrv)
{
	if (!inPrv || !outPrv)
	{
		return C_FALSE;
	}

	if (BN_num_bytes(inPrv) != GENERAL_256BIT_32BYTE_SIZE)
	{
		return C_FALSE;
	}
	BN_bn2bin(inPrv, outPrv->r);
	std::reverse(std::begin(outPrv->r), std::end(outPrv->r));

	return C_TRUE;
}

int ECKeyPubOpenSSL2General(const EC_POINT *inPub, general_secp256r1_public_t *outPub, ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || !inPub || !outPub)
	{
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	BIGNUM* pubX = BN_new();
	BIGNUM* pubY = BN_new();
	if (!pubX || 
		!pubY ||
		!EC_POINT_get_affine_coordinates_GFp(eccCtx->m_grp, inPub, pubX, pubY, eccCtx->m_bnCtx) ||
		BN_num_bytes(pubX) != GENERAL_256BIT_32BYTE_SIZE ||
		BN_num_bytes(pubY) != GENERAL_256BIT_32BYTE_SIZE)
	{
		BN_free(pubX);
		BN_free(pubY);
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	BN_bn2bin(pubX, outPub->x);
	BN_bn2bin(pubY, outPub->y);
	std::reverse(std::begin(outPub->x), std::end(outPub->x));
	std::reverse(std::begin(outPub->y), std::end(outPub->y));

	BN_free(pubX);
	BN_free(pubY);
	CloseTempContext(inCtx, eccCtx);

	return C_TRUE;
}

int ECKeyPairOpenSSL2General(const EC_KEY *inKeyPair, general_secp256r1_private_t *outPrv, general_secp256r1_public_t *outPub, ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || 
		!inKeyPair ||
		(!outPrv && !outPub))
	{
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	if (outPrv)
	{
		const BIGNUM *prv = EC_KEY_get0_private_key(inKeyPair);
		if (prv == nullptr ||
			!ECKeyPrvOpenSSL2General(prv, outPrv))
		{
			CloseTempContext(inCtx, eccCtx);
			return C_FALSE;
		}
	}

	if (outPub)
	{
		const EC_POINT *pub = EC_KEY_get0_public_key(inKeyPair);
		if (pub == nullptr ||
			!ECKeyPubOpenSSL2General(pub, outPub, eccCtx))
		{
			CloseTempContext(inCtx, eccCtx);
			return C_FALSE;
		}
	}

	CloseTempContext(inCtx, eccCtx);
	return C_TRUE;
}

int ECKeyPrvGeneral2OpenSSL(const general_secp256r1_private_t * inPrv, BIGNUM * outPrv)
{
	if (!inPrv || !outPrv)
	{
		return C_FALSE;
	}

	std::vector<uint8_t> buffer(std::rbegin(inPrv->r), std::rend(inPrv->r));

	return BN_bin2bn(buffer.data(), GENERAL_256BIT_32BYTE_SIZE, outPrv) != nullptr ? C_TRUE : C_FALSE;
}

int ECKeyPubGeneral2OpenSSL(const general_secp256r1_public_t *inPub, EC_POINT *outPub, ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || !inPub || !outPub)
	{
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	std::vector<uint8_t> buffer(std::rbegin(inPub->x), std::rend(inPub->x));

	BIGNUM* pubX = BN_new();
	BIGNUM* pubY = BN_new();
	if (!pubX || 
		!pubY ||
		!BN_bin2bn(buffer.data(), GENERAL_256BIT_32BYTE_SIZE, pubX))
	{
		BN_free(pubX);
		BN_free(pubY);
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	buffer.assign(std::rbegin(inPub->y), std::rend(inPub->y));

	if (!BN_bin2bn(buffer.data(), GENERAL_256BIT_32BYTE_SIZE, pubY) ||
		!EC_POINT_set_affine_coordinates_GFp(eccCtx->m_grp, outPub, pubX, pubY, eccCtx->m_bnCtx))
	{
		BN_free(pubX);
		BN_free(pubY);
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	BN_free(pubX);
	BN_free(pubY);
	CloseTempContext(inCtx, eccCtx);

	return C_TRUE;
}

int ECKeyPubGeneral2OpenSSL(const general_secp256r1_public_t *inPub, EC_KEY *outKeyPair, ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	int opensslRes = 0;

	if (!eccCtx || !inPub || !outKeyPair ||
		!EC_KEY_set_group(outKeyPair, eccCtx->m_grp))
	{
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	EC_POINT* pub = EC_POINT_new(eccCtx->m_grp);
	if (!pub ||
		!ECKeyPubGeneral2OpenSSL(inPub, pub, eccCtx) ||
		!EC_KEY_set_public_key(outKeyPair, pub))
	{
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	EC_POINT_free(pub);
	CloseTempContext(inCtx, eccCtx);
	return C_TRUE;
}

int ECKeyPairGeneral2OpenSSL(const general_secp256r1_private_t *inPrv, const general_secp256r1_public_t *inPub, EC_KEY *outKeyPair, ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || !inPrv || !outKeyPair ||
		!EC_KEY_set_group(outKeyPair, eccCtx->m_grp))
	{
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	BIGNUM* prvR = BN_new();
	EC_POINT* pub = EC_POINT_new(eccCtx->m_grp);
	if (!prvR || !pub)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	if (!ECKeyPrvGeneral2OpenSSL(inPrv, prvR))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	if ((!inPub && !ECKeyGetPubFromPrv(prvR, pub, eccCtx)) ||
		(inPub && !ECKeyPubGeneral2OpenSSL(inPub, pub, eccCtx)))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	if (!EC_KEY_set_private_key(outKeyPair, prvR) ||
		!EC_KEY_set_public_key(outKeyPair, pub))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	BN_free(prvR);
	EC_POINT_free(pub);
	CloseTempContext(inCtx, eccCtx);
	return C_TRUE;
}

int ECKeyGetPubFromPrv(const BIGNUM* inPrv, EC_POINT* outPub, ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || !inPrv || !outPub)
	{
		CloseTempContext(inCtx, eccCtx);
		return C_FALSE;
	}

	int opensslRes = EC_POINT_mul(eccCtx->m_grp, outPub, inPrv, NULL, NULL, eccCtx->m_bnCtx);
	CloseTempContext(inCtx, eccCtx);

	return opensslRes;
}


