//#if ENCLAVE_PLATFORM_SGX

#include "../Crypto.h"
#include "../../../Common/Tools/Crypto.h"

#include <iterator>

#include <sgx_utils.h>
#include <sgx_trts.h>
#include <sgx_tcrypto.h>

#include "../../../Common/SGX/RuntimeError.h"

using namespace Decent;
using namespace Decent::Tools;

namespace
{
	sgx_report_t ConstructSelfSgxReport()
	{
		sgx_report_t res;
		sgx_status_t sgxRet = sgx_create_report(nullptr, nullptr, &res);
		if (sgxRet != SGX_SUCCESS)
		{
			throw RuntimeException(Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_create_report"));
		}

		return res;
	}
}

namespace Decent
{
	namespace Sgx
	{
		const sgx_report_t& GetSelfSgxReport()
		{
			static sgx_report_t inst = ConstructSelfSgxReport();

			return inst;
		}
	}
}

const std::vector<uint8_t>& Tools::GetSelfHash()
{
	static const std::vector<uint8_t> gsk_selfHash(std::begin(Sgx::GetSelfSgxReport().body.mr_enclave.m), std::end(Sgx::GetSelfSgxReport().body.mr_enclave.m));

	return gsk_selfHash;
}

void Tools::SecureRand(void * buf, size_t size)
{
	DECENT_CHECK_SGX_FUNC_CALL_ERROR(sgx_read_rand, static_cast<unsigned char*>(buf), size);
}

void Tools::detail::PlatformAesGcmEncrypt(const void * keyPtr, const size_t keySize,
	const void * srcPtr, const size_t srcSize, 
	void * destPtr, 
	const void * ivPtr, const size_t ivSize, 
	const void * addPtr, const size_t addSize, 
	void * macPtr, const size_t macSize)
{
	if (keySize != sizeof(sgx_aes_gcm_128bit_key_t))
	{
		throw RuntimeException("Unsupported key size is given to PlatformAesGcmEncrypt.");
	}
	if (macSize != sizeof(sgx_aes_gcm_128bit_tag_t))
	{
		throw RuntimeException("Unsupported MAC size is given to PlatformAesGcmEncrypt.");
	}
	if (srcSize > UINT32_MAX || ivSize > UINT32_MAX || addSize > UINT32_MAX)
	{
		throw RuntimeException("Either source size, IV size, or addtional auth data size given to PlatformAesGcmEncrypt is too big to supported by SGX.");
	}

	const sgx_aes_gcm_128bit_key_t *p_key = static_cast<const sgx_aes_gcm_128bit_key_t*>(keyPtr);
	sgx_aes_gcm_128bit_tag_t *p_out_mac = static_cast<sgx_aes_gcm_128bit_tag_t*>(macPtr);

	sgx_status_t sgxRet = sgx_rijndael128GCM_encrypt(p_key,
		static_cast<const uint8_t*>(srcPtr), static_cast<const uint32_t>(srcSize), static_cast<uint8_t*>(destPtr),
		static_cast<const uint8_t*>(ivPtr), static_cast<const uint32_t>(ivSize),
		static_cast<const uint8_t*>(addPtr), static_cast<const uint32_t>(addSize),
		p_out_mac);
	if (sgxRet != SGX_SUCCESS)
	{
		throw RuntimeException(Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_rijndael128GCM_encrypt"));
	}
}

void Tools::detail::PlatformAesGcmDecrypt(const void * keyPtr, const size_t keySize,
	const void * srcPtr, const size_t srcSize, 
	void * destPtr, 
	const void * ivPtr, const size_t ivSize, 
	const void * addPtr, const size_t addSize, 
	const void * macPtr, const size_t macSize)
{
	if (keySize != sizeof(sgx_aes_gcm_128bit_key_t))
	{
		throw RuntimeException("Unsupported key size is given to PlatformAesGcmDecrypt.");
	}
	if (macSize != sizeof(sgx_aes_gcm_128bit_tag_t))
	{
		throw RuntimeException("Unsupported MAC size is given to PlatformAesGcmDecrypt.");
	}
	if (srcSize > UINT32_MAX || ivSize > UINT32_MAX || addSize > UINT32_MAX)
	{
		throw RuntimeException("Either source size, IV size, or addtional auth data size given to PlatformAesGcmEncrypt is too big to supported by SGX.");
	}

	const sgx_aes_gcm_128bit_key_t *p_key = static_cast<const sgx_aes_gcm_128bit_key_t*>(keyPtr);
	const sgx_aes_gcm_128bit_tag_t *p_in_mac = static_cast<const sgx_aes_gcm_128bit_tag_t*>(macPtr);

	sgx_status_t sgxRet = sgx_rijndael128GCM_decrypt(p_key,
		static_cast<const uint8_t*>(srcPtr), static_cast<const uint32_t>(srcSize), static_cast<uint8_t*>(destPtr),
		static_cast<const uint8_t*>(ivPtr), static_cast<const uint32_t>(ivSize),
		static_cast<const uint8_t*>(addPtr), static_cast<const uint32_t>(addSize),
		p_in_mac);
	if (sgxRet != SGX_SUCCESS)
	{
		throw RuntimeException(Sgx::ConstructSimpleErrorMsg(sgxRet, "sgx_rijndael128GCM_decrypt"));
	}
}

//#endif //ENCLAVE_PLATFORM_SGX
