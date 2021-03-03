#ifdef ENCLAVE_ENVIRONMENT

#ifdef ENCLAVE_SGX_ENVIRONMENT

#include <mbedTLScpp/Internal/PlatformIntel/Drng.hpp>
#include <mbedtls/entropy.h>

extern "C" int mbedtls_hardware_poll(void* data, unsigned char* output, size_t len, size_t * olen)
{
	(void)data;

	try
	{
		*olen = mbedTLScpp::Internal::PlatformIntel::ReadSeed(output, len);
	}
	catch (...)
	{
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	}

	return MBEDTLS_EXIT_SUCCESS;
}

#include <type_traits>

#include <mbedTLScpp/DefaultRbg.hpp>
#include <mbedTLScpp/LibInitializer.hpp>

static_assert(std::is_same<mbedTLScpp::DefaultRbg, Decent::SgxRbg>::value,
	"Must use SGX random bit generator.");
static_assert(std::is_same<mbedTLScpp::DefaultThreadingSubInitializer, Decent::SgxMutexIntfInitializer>::value,
	"Must use SGX mutex.");

#endif //ENCLAVE_SGX_ENVIRONMENT

#endif // ENCLAVE_ENVIRONMENT

