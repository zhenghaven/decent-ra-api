#include "SGXOpenSSLConversions.h"

#include <xutility>
#include <vector>
#include <cstdint>

#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include <sgx_tcrypto.h>

struct DecentEccContext
{
	EC_GROUP* m_grp;
	BN_CTX* m_bnCtx;

	DecentEccContext() :
		m_grp(EC_GROUP_new_by_curve_name(SGX_ECC256_CURVE_NAME)),
		m_bnCtx(BN_CTX_new())
	{}

	~DecentEccContext()
	{
		EC_GROUP_free(m_grp);
		BN_CTX_free(m_bnCtx);
	}
};

bool ECKeyOpenContext(sgx_ecc_state_handle_t * ctxPtr)
{
	if (ctxPtr == nullptr)
	{
		return false;
	}

	DecentEccContext* ctx = new DecentEccContext;
	if (ctx->m_grp == nullptr ||
		ctx->m_bnCtx == nullptr)
	{
		delete ctx;
		return false;
	}

	*ctxPtr = ctx;
	return true;
}

void ECKeyCloseContext(sgx_ecc_state_handle_t inCtx)
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
	sgx_ecc_state_handle_t tmpPtr = nullptr;
	if (!ECKeyOpenContext(&tmpPtr))
	{
		return nullptr;
	}

	return reinterpret_cast<DecentEccContext*>(tmpPtr);
}

static inline void CloseTempContext(sgx_ecc_state_handle_t inCtx, DecentEccContext* eccCtx)
{
	if (inCtx == nullptr)
	{
		ECKeyCloseContext(eccCtx);
	}
}

bool ECKeyPrvOpenSSL2SGX(const BIGNUM *inPrv, sgx_ec256_private_t *outPrv)
{
	if (!inPrv || !outPrv)
	{
		return false;
	}

	int prvSize = BN_num_bytes(inPrv);
	if (prvSize != SGX_ECP256_KEY_SIZE)
	{
		return false;
	}
	BN_bn2bin(inPrv, outPrv->r);
	std::reverse(std::begin(outPrv->r), std::end(outPrv->r));

	return true;
}

bool ECKeyPubOpenSSL2SGX(const EC_POINT *inPub, sgx_ec256_public_t *outPub, sgx_ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || !inPub || !outPub)
	{
		return false;
	}

	int opensslRes = 0;

	BIGNUM* pubX = BN_new();
	BIGNUM* pubY = BN_new();
	if (!pubX || !pubY)
	{
		BN_free(pubX);
		BN_free(pubY);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	opensslRes = EC_POINT_get_affine_coordinates_GFp(eccCtx->m_grp, inPub, pubX, pubY, eccCtx->m_bnCtx);
	if (opensslRes != 1)
	{
		BN_free(pubX);
		BN_free(pubY);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	if (BN_num_bytes(pubX) != SGX_ECP256_KEY_SIZE ||
		BN_num_bytes(pubY) != SGX_ECP256_KEY_SIZE)
	{
		BN_free(pubX);
		BN_free(pubY);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	BN_bn2bin(pubX, outPub->gx);
	BN_bn2bin(pubY, outPub->gy);
	std::reverse(std::begin(outPub->gx), std::end(outPub->gx));
	std::reverse(std::begin(outPub->gy), std::end(outPub->gy));

	BN_free(pubX);
	BN_free(pubY);
	CloseTempContext(inCtx, eccCtx);

	return true;
}

bool ECKeyPrvSGX2OpenSSL(const sgx_ec256_private_t *inPrv, BIGNUM *outPrv)
{
	if (!inPrv || !outPrv)
	{
		return false;
	}

	std::vector<uint8_t> buffer(SGX_ECP256_KEY_SIZE, 0);

	std::memcpy(&buffer[0], inPrv->r, SGX_ECP256_KEY_SIZE);
	std::reverse(buffer.begin(), buffer.end());
	BN_bin2bn(buffer.data(), SGX_ECP256_KEY_SIZE, outPrv);

	return true;
}

bool ECKeyPubSGX2OpenSSL(const sgx_ec256_public_t *inPub, EC_POINT *outPub, sgx_ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || !inPub || !outPub)
	{
		return false;
	}

	int opensslRes = 0;

	BIGNUM* pubX = BN_new();
	BIGNUM* pubY = BN_new();
	if (!pubX || !pubY)
	{
		BN_free(pubX);
		BN_free(pubY);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	std::vector<uint8_t> buffer(SGX_ECP256_KEY_SIZE, 0);

	std::memcpy(&buffer[0], inPub->gx, SGX_ECP256_KEY_SIZE);
	std::reverse(buffer.begin(), buffer.end());
	BN_bin2bn(buffer.data(), SGX_ECP256_KEY_SIZE, pubX);

	std::memcpy(&buffer[0], inPub->gy, SGX_ECP256_KEY_SIZE);
	std::reverse(buffer.begin(), buffer.end());
	BN_bin2bn(buffer.data(), SGX_ECP256_KEY_SIZE, pubY);

	opensslRes = EC_POINT_set_affine_coordinates_GFp(eccCtx->m_grp, outPub, pubX, pubY, eccCtx->m_bnCtx);
	if (opensslRes != 1)
	{
		BN_free(pubX);
		BN_free(pubY);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	BN_free(pubX);
	BN_free(pubY);
	CloseTempContext(inCtx, eccCtx);

	return true;
}

bool ECKeyGetPubFromPrv(const BIGNUM* inPrv, EC_POINT* outPub, sgx_ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || !inPrv || !outPub)
	{
		return false;
	}

	int opensslRes = 0;

	opensslRes = EC_POINT_mul(eccCtx->m_grp, outPub, inPrv, NULL, NULL, eccCtx->m_bnCtx);

	if (opensslRes != 1)
	{
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	CloseTempContext(inCtx, eccCtx);
	return true;
}

bool ECKeyPairOpenSSL2SGX(const EC_KEY *inKeyPair, sgx_ec256_private_t *outPrv, sgx_ec256_public_t *outPub, sgx_ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || !inKeyPair || !outPrv || !outPub)
	{
		return false;
	}

	const BIGNUM *prv = EC_KEY_get0_private_key(inKeyPair);
	if (prv == nullptr)
	{
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	const EC_POINT *pub = EC_KEY_get0_public_key(inKeyPair);
	if (pub == nullptr)
	{
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	if (!ECKeyPrvOpenSSL2SGX(prv, outPrv))
	{
		CloseTempContext(inCtx, eccCtx);
		return false;
	}
	if (!ECKeyPubOpenSSL2SGX(pub, outPub, eccCtx))
	{
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	CloseTempContext(inCtx, eccCtx);
	return true;
}

bool ECKeyPairSGX2OpenSSL(const sgx_ec256_private_t *inPrv, const sgx_ec256_public_t *inPub, EC_KEY *outKeyPair, sgx_ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	int opensslRes = 0;

	if (!eccCtx || !inPrv || !inPub || !outKeyPair)
	{
		return false;
	}

	opensslRes = EC_KEY_set_group(outKeyPair, eccCtx->m_grp);
	if (opensslRes != 1)
	{
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	BIGNUM* prvR = BN_new();
	EC_POINT* pub = EC_POINT_new(eccCtx->m_grp);
	if (!prvR || !pub)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	if (!ECKeyPrvSGX2OpenSSL(inPrv, prvR))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}
	if (!ECKeyPubSGX2OpenSSL(inPub, pub, eccCtx))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}
	opensslRes = EC_KEY_set_private_key(outKeyPair, prvR);
	if (opensslRes != 1)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}
	opensslRes = EC_KEY_set_public_key(outKeyPair, pub);
	if (opensslRes != 1)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	BN_free(prvR);
	EC_POINT_free(pub);
	CloseTempContext(inCtx, eccCtx);
	return true;
}

bool ECKeyPairSGX2OpenSSL(const sgx_ec256_private_t *inPrv, EC_KEY *outKeyPair, sgx_ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	if (!eccCtx || !inPrv || !outKeyPair)
	{
		return false;
	}

	int opensslRes = 0;

	opensslRes = EC_KEY_set_group(outKeyPair, eccCtx->m_grp);
	if (opensslRes != 1)
	{
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	BIGNUM* prvR = BN_new();
	EC_POINT* pub = EC_POINT_new(eccCtx->m_grp);
	if (!prvR || !pub)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	if (!ECKeyPrvSGX2OpenSSL(inPrv, prvR))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	if (!ECKeyGetPubFromPrv(prvR, pub, eccCtx))
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	opensslRes = EC_KEY_set_private_key(outKeyPair, prvR);
	if (opensslRes != 1)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}
	opensslRes = EC_KEY_set_public_key(outKeyPair, pub);
	if (opensslRes != 1)
	{
		BN_free(prvR);
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	BN_free(prvR);
	EC_POINT_free(pub);
	CloseTempContext(inCtx, eccCtx);
	return true;
}

bool ECKeyPubSGX2OpenSSL(const sgx_ec256_public_t *inPub, EC_KEY *outKeyPair, sgx_ecc_state_handle_t inCtx)
{
	DecentEccContext* eccCtx = (inCtx == nullptr) ? OpenTempContext() : reinterpret_cast<DecentEccContext*>(inCtx);

	int opensslRes = 0;

	if (!eccCtx || !inPub || !outKeyPair)
	{
		return false;
	}

	opensslRes = EC_KEY_set_group(outKeyPair, eccCtx->m_grp);
	if (opensslRes != 1)
	{
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	EC_POINT* pub = EC_POINT_new(eccCtx->m_grp);
	if (!pub)
	{
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	if (!ECKeyPubSGX2OpenSSL(inPub, pub, eccCtx))
	{
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	opensslRes = EC_KEY_set_public_key(outKeyPair, pub);
	if (opensslRes != 1)
	{
		EC_POINT_free(pub);
		CloseTempContext(inCtx, eccCtx);
		return false;
	}

	EC_POINT_free(pub);
	CloseTempContext(inCtx, eccCtx);
	return true;
}

bool ECKeyCalcSharedKey(EVP_PKEY* inKey, EVP_PKEY* inPeerKey, sgx_ec256_dh_shared_t *outSharedkey)
{
	if (!inKey || !inPeerKey)
	{
		return false;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(inKey, nullptr);
	if (!ctx)
	{
		return false;
	}

	if (EVP_PKEY_derive_init(ctx) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (EVP_PKEY_derive_set_peer(ctx, inPeerKey) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	size_t keySize = 0;
	if (EVP_PKEY_derive(ctx, NULL, &keySize) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (keySize != SGX_ECP256_KEY_SIZE)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	if (EVP_PKEY_derive(ctx, outSharedkey->s, &keySize) <= 0)
	{
		EVP_PKEY_CTX_free(ctx);
		return false;
	}

	std::reverse(std::begin(outSharedkey->s), std::end(outSharedkey->s));

	EVP_PKEY_CTX_free(ctx);
	return true;
}

bool ECKeySignOpenSSL2SGX(const ECDSA_SIG * inSign, sgx_ec256_signature_t * outSign)
{
	if (!inSign || !outSign)
	{
		return false;
	}

	const BIGNUM* r = nullptr;
	const BIGNUM* s = nullptr;
	ECDSA_SIG_get0(inSign, &r, &s);

	if (BN_num_bytes(r) != SGX_ECP256_KEY_SIZE ||
		BN_num_bytes(s) != SGX_ECP256_KEY_SIZE)
	{
		return false;
	}

	uint8_t* signX = reinterpret_cast<uint8_t*>(outSign->x);
	uint8_t* signY = reinterpret_cast<uint8_t*>(outSign->y);
	BN_bn2bin(r, signX);
	BN_bn2bin(s, signY);
	std::reverse(&signX[0], &signX[SGX_ECP256_KEY_SIZE]);
	std::reverse(&signY[0], &signY[SGX_ECP256_KEY_SIZE]);

	return true;
}

bool ECKeySignSGX2OpenSSL(const sgx_ec256_signature_t * inSign, ECDSA_SIG * outSign)
{
	if (!inSign || !outSign)
	{
		return false;
	}

	BIGNUM* r = BN_new();
	BIGNUM* s = BN_new();
	if (!r || !s)
	{
		BN_free(r);
		BN_free(s);
		return false;
	}

	std::vector<uint8_t> buffer(SGX_ECP256_KEY_SIZE, 0);

	std::memcpy(buffer.data(), inSign->x, buffer.size());
	std::reverse(buffer.begin(), buffer.end());
	BN_bin2bn(buffer.data(), buffer.size(), r);

	std::memcpy(buffer.data(), inSign->y, buffer.size());
	std::reverse(buffer.begin(), buffer.end());
	BN_bin2bn(buffer.data(), buffer.size(), s);

	if (BN_num_bytes(r) != SGX_ECP256_KEY_SIZE ||
		BN_num_bytes(s) != SGX_ECP256_KEY_SIZE)
	{
		BN_free(r);
		BN_free(s);
		return false;
	}

	int opensslRes = 0;

	opensslRes = ECDSA_SIG_set0(outSign, r, s); //The ownership of r and s is changed here!
	if (opensslRes != 1)
	{
		BN_free(r);
		BN_free(s);
		return false;
	}

	return true;
}
