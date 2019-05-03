#include "ErrorCode.h"

#include <string>

#include "../RuntimeException.h"

using namespace Decent;

const char* Sgx::GetErrorMessage(const sgx_status_t code)
{
	switch (code)
	{
	//0x0...
	case SGX_SUCCESS:
		return "Success.";

	//0x0...
	case SGX_ERROR_UNEXPECTED:
		return "Unexpected error.";
	case SGX_ERROR_INVALID_PARAMETER:
		return "The parameter is incorrect.";
	case SGX_ERROR_OUT_OF_MEMORY:
		return "Not enough memory is available to complete this operation.";
	case SGX_ERROR_ENCLAVE_LOST:
		return "Enclave lost after power transition or used in child process created by linux:fork().";
	case SGX_ERROR_INVALID_STATE:
		return "SGX API is invoked in incorrect order or state.";
#ifdef _WIN32
	case SGX_ERROR_HYPERV_ENABLED:
		return "Win10 platform with Hyper-V enabled.";
	case SGX_ERROR_FEATURE_NOT_SUPPORTED:
		return "Feature is not supported on this platform.";
#endif

	//0x1...
	case SGX_ERROR_INVALID_FUNCTION:
		return "The ecall/ocall index is invalid.";
	case SGX_ERROR_OUT_OF_TCS:
		return "The enclave is out of TCS.";
	case SGX_ERROR_ENCLAVE_CRASHED:
		return "The enclave is crashed.";
	case SGX_ERROR_ECALL_NOT_ALLOWED:
		return "The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization.";
	case SGX_ERROR_OCALL_NOT_ALLOWED:
		return "The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling.";
#ifndef _WIN32
	case SGX_ERROR_STACK_OVERRUN:
		return "The enclave is running out of stack";
#endif

	//0x2...
	case SGX_ERROR_UNDEFINED_SYMBOL:
		return "The enclave image has undefined symbol.";
	case SGX_ERROR_INVALID_ENCLAVE:
		return "The enclave image is not correct.";
	case SGX_ERROR_INVALID_ENCLAVE_ID:
		return "The enclave id is invalid.";
	case SGX_ERROR_INVALID_SIGNATURE:
		return "The signature is invalid.";
	case SGX_ERROR_NDEBUG_ENCLAVE:
		return "The enclave is signed as product enclave, and can not be created as debuggable enclave.";

	case SGX_ERROR_OUT_OF_EPC:
		return "Not enough EPC is available to load the enclave.";
	case SGX_ERROR_NO_DEVICE:
		return "Can't open SGX device.";
	case SGX_ERROR_MEMORY_MAP_CONFLICT:
		return "Page mapping failed in driver.";
	case SGX_ERROR_INVALID_METADATA:
		return "The metadata is incorrect.";
	case SGX_ERROR_DEVICE_BUSY:
		return "Device is busy, mostly EINIT failed.";

	case SGX_ERROR_INVALID_VERSION:
		return "Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform.";
	case SGX_ERROR_MODE_INCOMPATIBLE:
		return "The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS.";
	case SGX_ERROR_ENCLAVE_FILE_ACCESS:
		return "Can't open enclave file.";
	case SGX_ERROR_INVALID_MISC:
		return "The MiscSelct/MiscMask settings are not correct.";
#ifndef _WIN32
	case SGX_ERROR_INVALID_LAUNCH_TOKEN:
		return "The launch token is not correct.";
#endif

	//0x3...
	case SGX_ERROR_MAC_MISMATCH:
		return "Indicates verification error for reports, sealed datas, etc";
	case SGX_ERROR_INVALID_ATTRIBUTE:
		return "The enclave is not authorized";
	case SGX_ERROR_INVALID_CPUSVN:
		return "The cpu svn is beyond platform's cpu svn value";
	case SGX_ERROR_INVALID_ISVSVN:
		return "The isv svn is greater than the enclave's isv svn";
	case SGX_ERROR_INVALID_KEYNAME:
		return "The key name is an unsupported value";
	
	//0x4...
	case SGX_ERROR_SERVICE_UNAVAILABLE:
		return "Indicates aesm didn't respond or the requested service is not supported";
	case SGX_ERROR_SERVICE_TIMEOUT:
		return "The request to aesm timed out";
	case SGX_ERROR_AE_INVALID_EPIDBLOB:
		return "Indicates epid blob verification error";
	case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
		return "Enclave has no privilege to get launch token";
	case SGX_ERROR_EPID_MEMBER_REVOKED:
		return "The EPID group membership is revoked.";

	case SGX_ERROR_UPDATE_NEEDED:
		return "SGX needs to be updated";
	case SGX_ERROR_NETWORK_FAILURE:
		return "Network connecting or proxy setting issue is encountered";
	case SGX_ERROR_AE_SESSION_INVALID:
		return "Session is invalid or ended by server";
	case SGX_ERROR_BUSY:
		return "The requested service is temporarily not availabe";
	case SGX_ERROR_MC_NOT_FOUND:
		return "The Monotonic Counter doesn't exist or has been invalided";

	case SGX_ERROR_MC_NO_ACCESS_RIGHT:
		return "Caller doesn't have the access right to specified VMC";
	case SGX_ERROR_MC_USED_UP:
		return "Monotonic counters are used out";
	case SGX_ERROR_MC_OVER_QUOTA:
		return "Monotonic counters exceeds quota limitation";
	case SGX_ERROR_KDF_MISMATCH:
		return "Key derivation function doesn't match during key exchange";
	case SGX_ERROR_UNRECOGNIZED_PLATFORM:
		return "EPID Provisioning failed due to platform not recognized by backend server";

#ifdef _WIN32
	case SGX_ERROR_SM_SERVICE_CLOSED:
		return "The secure message service instance was closed";
	case SGX_ERROR_SM_SERVICE_UNAVAILABLE:
		return "The secure message service applet doesn't have existing session";
	case SGX_ERROR_SM_SERVICE_UNCAUGHT_EXCEPTION:
		return "The secure message service instance was terminated with an uncaught exception";
	case SGX_ERROR_SM_SERVICE_RESPONSE_OVERFLOW:
		return "The response data of the service applet is too much";
	case SGX_ERROR_SM_SERVICE_INTERNAL_ERROR:
		return "The secure message service got an internal error";
#endif
	
	//0x5...
	case SGX_ERROR_NO_PRIVILEGE:
		return "Not enough privilege to perform the operation";

	//0x7...
	case SGX_ERROR_FILE_BAD_STATUS:
		return "The file is in bad status, run sgx_clearerr to try and fix it";
	case SGX_ERROR_FILE_NO_KEY_ID:
		return "The Key ID field is all zeros, can't re-generate the encryption key";
	case SGX_ERROR_FILE_NAME_MISMATCH:
		return "The current file name is different then the original file name (not allowed, substitution attack)";
	case SGX_ERROR_FILE_NOT_SGX_FILE:
		return "The file is not an SGX file";
	case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE:
		return "A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)";

	case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE:
		return "A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)";
	case SGX_ERROR_FILE_RECOVERY_NEEDED:
		return "When openeing the file, recovery is needed, but the recovery process failed";
	case SGX_ERROR_FILE_FLUSH_FAILED:
		return "fflush operation (to disk) failed (only used when no EXXX is returned)";
	case SGX_ERROR_FILE_CLOSE_FAILED:
		return "fclose operation (to disk) failed (only used when no EXXX is returned)";
	
	default:
		throw Decent::RuntimeException("Unknown SGX error code - " + std::to_string(code) + ".");
	}
}

constexpr char const gsk_notApplicableMsg[] = "N/A";

const char * Decent::Sgx::GetErrorSolution(const sgx_status_t code)
{
	switch (code)
	{
		//0x0...
	case SGX_SUCCESS:
		return gsk_notApplicableMsg;

		//0x0...
	case SGX_ERROR_UNEXPECTED:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_PARAMETER:
		return gsk_notApplicableMsg;
	case SGX_ERROR_OUT_OF_MEMORY:
		return gsk_notApplicableMsg;
	case SGX_ERROR_ENCLAVE_LOST:
		return "Please refer to the sample \"PowerTransition\" for details.";
	case SGX_ERROR_INVALID_STATE:
		return gsk_notApplicableMsg;
#ifdef _WIN32
	case SGX_ERROR_HYPERV_ENABLED:
		return gsk_notApplicableMsg;
	case SGX_ERROR_FEATURE_NOT_SUPPORTED:
		return gsk_notApplicableMsg;
#endif

		//0x1...
	case SGX_ERROR_INVALID_FUNCTION:
		return gsk_notApplicableMsg;
	case SGX_ERROR_OUT_OF_TCS:
		return gsk_notApplicableMsg;
	case SGX_ERROR_ENCLAVE_CRASHED:
		return gsk_notApplicableMsg;
	case SGX_ERROR_ECALL_NOT_ALLOWED:
		return gsk_notApplicableMsg;
	case SGX_ERROR_OCALL_NOT_ALLOWED:
		return gsk_notApplicableMsg;
#ifndef _WIN32
	case SGX_ERROR_STACK_OVERRUN:
		return gsk_notApplicableMsg;
#endif

		//0x2...
	case SGX_ERROR_UNDEFINED_SYMBOL:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_ENCLAVE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_ENCLAVE_ID:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_SIGNATURE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_NDEBUG_ENCLAVE:
		return gsk_notApplicableMsg;

	case SGX_ERROR_OUT_OF_EPC:
		return gsk_notApplicableMsg;
	case SGX_ERROR_NO_DEVICE:
		return "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards.";
	case SGX_ERROR_MEMORY_MAP_CONFLICT:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_METADATA:
		return gsk_notApplicableMsg;
	case SGX_ERROR_DEVICE_BUSY:
		return gsk_notApplicableMsg;

	case SGX_ERROR_INVALID_VERSION:
		return gsk_notApplicableMsg;
	case SGX_ERROR_MODE_INCOMPATIBLE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_ENCLAVE_FILE_ACCESS:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_MISC:
		return gsk_notApplicableMsg;
#ifndef _WIN32
	case SGX_ERROR_INVALID_LAUNCH_TOKEN:
		return gsk_notApplicableMsg;
#endif

		//0x3...
	case SGX_ERROR_MAC_MISMATCH:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_ATTRIBUTE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_CPUSVN:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_ISVSVN:
		return gsk_notApplicableMsg;
	case SGX_ERROR_INVALID_KEYNAME:
		return gsk_notApplicableMsg;

		//0x4...
	case SGX_ERROR_SERVICE_UNAVAILABLE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_SERVICE_TIMEOUT:
		return gsk_notApplicableMsg;
	case SGX_ERROR_AE_INVALID_EPIDBLOB:
		return gsk_notApplicableMsg;
	case SGX_ERROR_SERVICE_INVALID_PRIVILEGE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_EPID_MEMBER_REVOKED:
		return gsk_notApplicableMsg;
	case SGX_ERROR_UPDATE_NEEDED:
		return gsk_notApplicableMsg;
	case SGX_ERROR_NETWORK_FAILURE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_AE_SESSION_INVALID:
		return gsk_notApplicableMsg;
	case SGX_ERROR_BUSY:
		return gsk_notApplicableMsg;
	case SGX_ERROR_MC_NOT_FOUND:
		return gsk_notApplicableMsg;
	case SGX_ERROR_MC_NO_ACCESS_RIGHT:
		return gsk_notApplicableMsg;
	case SGX_ERROR_MC_USED_UP:
		return gsk_notApplicableMsg;
	case SGX_ERROR_MC_OVER_QUOTA:
		return gsk_notApplicableMsg;
	case SGX_ERROR_KDF_MISMATCH:
		return gsk_notApplicableMsg;
	case SGX_ERROR_UNRECOGNIZED_PLATFORM:
		return gsk_notApplicableMsg;
#ifdef _WIN32
	case SGX_ERROR_SM_SERVICE_CLOSED:
		return gsk_notApplicableMsg;
	case SGX_ERROR_SM_SERVICE_UNAVAILABLE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_SM_SERVICE_UNCAUGHT_EXCEPTION:
		return gsk_notApplicableMsg;
	case SGX_ERROR_SM_SERVICE_RESPONSE_OVERFLOW:
		return gsk_notApplicableMsg;
	case SGX_ERROR_SM_SERVICE_INTERNAL_ERROR:
		return gsk_notApplicableMsg;
#endif

		//0x5...
	case SGX_ERROR_NO_PRIVILEGE:
		return gsk_notApplicableMsg;

		//0x7...
	case SGX_ERROR_FILE_BAD_STATUS:
		return gsk_notApplicableMsg;
	case SGX_ERROR_FILE_NO_KEY_ID:
		return gsk_notApplicableMsg;
	case SGX_ERROR_FILE_NAME_MISMATCH:
		return gsk_notApplicableMsg;
	case SGX_ERROR_FILE_NOT_SGX_FILE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE:
		return gsk_notApplicableMsg;
	case SGX_ERROR_FILE_RECOVERY_NEEDED:
		return gsk_notApplicableMsg;
	case SGX_ERROR_FILE_FLUSH_FAILED:
		return gsk_notApplicableMsg;
	case SGX_ERROR_FILE_CLOSE_FAILED:
		return gsk_notApplicableMsg;

	default:
		throw Decent::RuntimeException("Unknown SGX error code - " + std::to_string(code) + ".");
	}
}

std::string Decent::Sgx::ConstructErrorMsg(sgx_status_t errCode, const std::string & funcName)
{
	return "SGX Runtime Error: From function, " + funcName + 
		"\nSGX Err Msg: " + GetErrorMessage(errCode) + 
		"\nHint: " + GetErrorSolution(errCode);
}

std::string Decent::Sgx::ConstructSimpleErrorMsg(sgx_status_t errCode, const std::string & funcName)
{
	return "SGX Runtime Error: From function, " + funcName +
		". SGX Err Msg: " + GetErrorMessage(errCode);
}
