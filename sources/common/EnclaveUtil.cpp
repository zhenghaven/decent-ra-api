#include "EnclaveUtil.h"

#include <map>

#include <sgx_uae_service.h>

#include "Common.h"

namespace
{
	std::map<sgx_status_t, std::pair<std::string, std::string> > g_sgxErrorMsg = 
	{
		//0x0...
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_SUCCESS, std::pair<std::string, std::string>("Success.", "")),
		
		//0x0...
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_UNEXPECTED, std::pair<std::string, std::string>("Unexpected error.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_PARAMETER, std::pair<std::string, std::string>("The parameter is incorrect.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_OUT_OF_MEMORY, std::pair<std::string, std::string>("Not enough memory is available to complete this operation.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_ENCLAVE_LOST, std::pair<std::string, std::string>("Enclave lost after power transition or used in child process created by linux:fork().", "Please refer to the sample \"PowerTransition\" for details.")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_STATE, std::pair<std::string, std::string>("SGX API is invoked in incorrect order or state.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_HYPERV_ENABLED, std::pair<std::string, std::string>("Win10 platform with Hyper-V enabled.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FEATURE_NOT_SUPPORTED, std::pair<std::string, std::string>("Feature is not supported on this platform.", "")),
		
		//0x1...
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_FUNCTION, std::pair<std::string, std::string>("The ecall/ocall index is invalid.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_OUT_OF_TCS, std::pair<std::string, std::string>("The enclave is out of TCS.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_ENCLAVE_CRASHED, std::pair<std::string, std::string>("The enclave is crashed.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_ECALL_NOT_ALLOWED, std::pair<std::string, std::string>("The ECALL is not allowed at this time, e.g. ecall is blocked by the dynamic entry table, or nested ecall is not allowed during initialization.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_OCALL_NOT_ALLOWED, std::pair<std::string, std::string>("The OCALL is not allowed at this time, e.g. ocall is not allowed during exception handling.", "")),
		
		//0x2...
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_UNDEFINED_SYMBOL, std::pair<std::string, std::string>("The enclave image has undefined symbol.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_ENCLAVE, std::pair<std::string, std::string>("The enclave image is not correct.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_ENCLAVE_ID, std::pair<std::string, std::string>("The enclave id is invalid.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_SIGNATURE, std::pair<std::string, std::string>("The signature is invalid.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_NDEBUG_ENCLAVE, std::pair<std::string, std::string>("The enclave is signed as product enclave, and can not be created as debuggable enclave.", "")),

		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_OUT_OF_EPC, std::pair<std::string, std::string>("Not enough EPC is available to load the enclave.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_NO_DEVICE, std::pair<std::string, std::string>("Can't open SGX device.", "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards.")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_MEMORY_MAP_CONFLICT, std::pair<std::string, std::string>("Page mapping failed in driver.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_METADATA, std::pair<std::string, std::string>("The metadata is incorrect.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_DEVICE_BUSY, std::pair<std::string, std::string>("Device is busy, mostly EINIT failed.", "")),

		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_VERSION, std::pair<std::string, std::string>("Metadata version is inconsistent between uRTS and sgx_sign or uRTS is incompatible with current platform.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_MODE_INCOMPATIBLE, std::pair<std::string, std::string>("The target enclave 32/64 bit mode or sim/hw mode is incompatible with the mode of current uRTS.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_ENCLAVE_FILE_ACCESS, std::pair<std::string, std::string>("Can't open enclave file.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_MISC, std::pair<std::string, std::string>("The MiscSelct/MiscMask settings are not correct.", "")),

		//0x3...
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_MAC_MISMATCH, std::pair<std::string, std::string>("Indicates verification error for reports, sealed datas, etc", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_ATTRIBUTE, std::pair<std::string, std::string>("The enclave is not authorized", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_CPUSVN, std::pair<std::string, std::string>("The cpu svn is beyond platform's cpu svn value", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_ISVSVN, std::pair<std::string, std::string>("The isv svn is greater than the enclave's isv svn", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_INVALID_KEYNAME, std::pair<std::string, std::string>("The key name is an unsupported value", "")),
		
		//0x4...
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_SERVICE_UNAVAILABLE, std::pair<std::string, std::string>("Indicates aesm didn't respond or the requested service is not supported", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_SERVICE_TIMEOUT, std::pair<std::string, std::string>("The request to aesm timed out", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_AE_INVALID_EPIDBLOB, std::pair<std::string, std::string>("Indicates epid blob verification error", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_SERVICE_INVALID_PRIVILEGE, std::pair<std::string, std::string>("Enclave has no privilege to get launch token", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_EPID_MEMBER_REVOKED, std::pair<std::string, std::string>("The EPID group membership is revoked.", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_UPDATE_NEEDED, std::pair<std::string, std::string>("SGX needs to be updated", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_NETWORK_FAILURE, std::pair<std::string, std::string>("Network connecting or proxy setting issue is encountered", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_AE_SESSION_INVALID, std::pair<std::string, std::string>("Session is invalid or ended by server", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_BUSY, std::pair<std::string, std::string>("The requested service is temporarily not availabe", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_MC_NOT_FOUND, std::pair<std::string, std::string>("The Monotonic Counter doesn't exist or has been invalided", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_MC_NO_ACCESS_RIGHT, std::pair<std::string, std::string>("Caller doesn't have the access right to specified VMC", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_MC_USED_UP, std::pair<std::string, std::string>("Monotonic counters are used out", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_MC_OVER_QUOTA, std::pair<std::string, std::string>("Monotonic counters exceeds quota limitation", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_KDF_MISMATCH, std::pair<std::string, std::string>("Key derivation function doesn't match during key exchange", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_UNRECOGNIZED_PLATFORM, std::pair<std::string, std::string>("EPID Provisioning failed due to platform not recognized by backend server", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_SM_SERVICE_CLOSED, std::pair<std::string, std::string>("The secure message service instance was closed", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_SM_SERVICE_UNAVAILABLE, std::pair<std::string, std::string>("The secure message service applet doesn't have existing session", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_SM_SERVICE_UNCAUGHT_EXCEPTION, std::pair<std::string, std::string>("The secure message service instance was terminated with an uncaught exception", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_SM_SERVICE_RESPONSE_OVERFLOW, std::pair<std::string, std::string>("The response data of the service applet is too much", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_SM_SERVICE_INTERNAL_ERROR, std::pair<std::string, std::string>("The secure message service got an internal error", "")),
		
		//0x5...
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_NO_PRIVILEGE, std::pair<std::string, std::string>("Not enough privilege to perform the operation", "")),
		
		//0x7...
		/* SGX errors are only used in the file API when there is no appropriate EXXX (EINVAL, EIO etc.) error code */
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FILE_BAD_STATUS, std::pair<std::string, std::string>("The file is in bad status, run sgx_clearerr to try and fix it", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FILE_NO_KEY_ID, std::pair<std::string, std::string>("The Key ID field is all zeros, can't re-generate the encryption key", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FILE_NAME_MISMATCH, std::pair<std::string, std::string>("The current file name is different then the original file name (not allowed, substitution attack)", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FILE_NOT_SGX_FILE, std::pair<std::string, std::string>("The file is not an SGX file", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE, std::pair<std::string, std::string>("A recovery file can't be opened, so flush operation can't continue (only used when no EXXX is returned)", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE, std::pair<std::string, std::string>("A recovery file can't be written, so flush operation can't continue (only used when no EXXX is returned)", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FILE_RECOVERY_NEEDED, std::pair<std::string, std::string>("When openeing the file, recovery is needed, but the recovery process failed", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FILE_FLUSH_FAILED, std::pair<std::string, std::string>("fflush operation (to disk) failed (only used when no EXXX is returned)", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_FILE_CLOSE_FAILED, std::pair<std::string, std::string>("fclose operation (to disk) failed (only used when no EXXX is returned)", "")),
		
		//0x8...
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_IPLDR_NOTENCRYPTED, std::pair<std::string, std::string>("sgx_create_encrypted_enclave was called but enclave dll is not encrypted", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_IPLDR_MAC_MISMATCH, std::pair<std::string, std::string>("sgx_create_encrypted_enclave was called but there was a verification error when decrypting the data", "")),
		std::pair<sgx_status_t, std::pair<std::string, std::string> >(SGX_ERROR_IPLDR_ENCRYPTED, std::pair<std::string, std::string>("sgx_create_enclave was called but enclave dll is encrypted", "")),
	};

	std::map<sgx_device_status_t, std::string> g_sgxDeviceStatus = 
	{
		std::pair<sgx_device_status_t, std::string>(SGX_ENABLED, "Enabled"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_REBOOT_REQUIRED, "A reboot is required to finish enabling SGX"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_LEGACY_OS, "SGX is disabled and a Software Control Interface is not available to enable it"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED, "SGX is not enabled on this platform. More details are unavailable."),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_SCI_AVAILABLE, "SGX is disabled, but a Software Control Interface is available to enable it"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_MANUAL_ENABLE, "SGX is disabled, but can be enabled manually in the BIOS setup"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_HYPERV_ENABLED, "Detected an unsupported version of Windows* 10 with Hyper-V enabled"),
		std::pair<sgx_device_status_t, std::string>(SGX_DISABLED_UNSUPPORTED_CPU, "SGX is not supported by this CPU"),
	};
}

std::string GetSGXErrorMessage(const sgx_status_t ret)
{
	if (g_sgxErrorMsg.find(ret) == g_sgxErrorMsg.end())
	{
		LOGE("Error: Cannot find the error message specified!");
		return "Error: Cannot find the error message specified!";
	}
	return g_sgxErrorMsg[ret].first;
}

std::string GetSGXDeviceStatusStr(const sgx_device_status_t ret)
{
	if (g_sgxDeviceStatus.find(ret) == g_sgxDeviceStatus.end())
	{
		LOGE("Error: Cannot find the status string specified!");
		return "Error: Cannot find the status string specified!";
	}
	return g_sgxDeviceStatus[ret];
}

sgx_status_t GetSGXDeviceStatus(sgx_device_status_t & res)
{
	return sgx_enable_device(&res);;
}
