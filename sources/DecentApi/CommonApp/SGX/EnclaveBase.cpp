#include "EnclaveBase.h"

#include <algorithm>
#include <thread>

#include <sgx_urts.h>
#include <sgx_eid.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>

#include <boost/filesystem/operations.hpp>

#include "../Tools/FileSystemUtil.h"
#include "../Tools/DiskFile.h"

#include "../../Common/Common.h"
#include "../../Common/Tools/DataCoding.h"
#include "../../Common/Net/Connection.h"
#include "../../Common/SGX/sgx_structs.h"

#include "EnclaveUtil.h"
#include "EnclaveRuntimeException.h"
#include "edl_decent_sgx_client.h"

using namespace Decent::Sgx;
using namespace Decent::Net;
using namespace Decent::Tools;

constexpr char EnclaveBase::sk_platformType[];

static void CheckFilePath(const fs::path& enclavePath, const fs::path& tokenPath)
{
	if (!fs::exists(enclavePath))
	{
		throw EnclaveRuntimeException(SGX_ERROR_INVALID_PARAMETER, "Enclave program file doesn't exist!");
	}
	if (!fs::exists(tokenPath.parent_path()))
	{
		fs::create_directories(tokenPath.parent_path());
	}
}

sgx_enclave_id_t EnclaveBase::LaunchEnclave(const fs::path& enclavePath, const fs::path& tokenPath)
{
#ifdef SIMULATING_ENCLAVE
	LOGW("Enclave is running under simulation mode!!\n");
#endif // SIMULATING_ENCLAVE

	CheckFilePath(enclavePath, tokenPath);

	sgx_enclave_id_t outEnclaveID;
	
	int needUpdateToken = 0;
	std::vector<uint8_t> tokenBuf(sizeof(sgx_launch_token_t), 0);
	if (!EnclaveBase::LoadToken(tokenPath, tokenBuf))
	{
		LOGW("Enclave App - %s, Read token from %s Failed!", enclavePath.string().c_str(), tokenPath.string().c_str());
	}

	LOGI("SGX Enclave Token: \n%s\n\n", SerializeStruct(tokenBuf.data(), sizeof(sgx_launch_token_t)).c_str());
	sgx_status_t enclaveRet = sgx_create_enclave(enclavePath.string().c_str(), SGX_DEBUG_FLAG, reinterpret_cast<sgx_launch_token_t*>(tokenBuf.data()), &needUpdateToken, &outEnclaveID, NULL);
	if (enclaveRet != SGX_SUCCESS)
	{
		throw EnclaveRuntimeException(enclaveRet, "sgx_create_enclave");
	}

	if (needUpdateToken)
	{
		LOGI("SGX Enclave Token (Updated): \n%s\n\n", SerializeStruct(tokenBuf.data(), sizeof(sgx_launch_token_t)).c_str());
		if (!EnclaveBase::UpdateToken(tokenPath, tokenBuf))
		{
			LOGW("Enclave App - %s, Write token to %s Failed!", enclavePath.string().c_str(), tokenPath.string().c_str());
		}
	}

	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_decent_sgx_client_enclave_init(outEnclaveID, &retval);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_enclave_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_enclave_init);

	return outEnclaveID;
}

EnclaveBase::EnclaveBase(const std::string& enclavePath, const std::string& tokenPath) :
	EnclaveBase(fs::path(enclavePath), fs::path(tokenPath))
{
}

EnclaveBase::EnclaveBase(const fs::path& enclavePath, const fs::path& tokenPath) :
	m_eid(EnclaveBase::LaunchEnclave(enclavePath, tokenPath)),
	m_enclavePath(enclavePath.generic_string())
{
}

EnclaveBase::EnclaveBase(const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName) :
	EnclaveBase(fs::path(enclavePath), GetKnownFolderPath(tokenLocType).append(tokenFileName))
{
}

EnclaveBase::~EnclaveBase()
{
	ecall_decent_sgx_client_enclave_terminate(m_eid);
	sgx_destroy_enclave(m_eid);
}

const char * EnclaveBase::GetPlatformType() const
{
	return sk_platformType;
}

uint32_t EnclaveBase::GetExGroupID()
{
	uint32_t res = 0;
	sgx_status_t enclaveRet = sgx_get_extended_epid_group_id(&res);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, sgx_get_extended_epid_group_id);

	return res;
}

bool EnclaveBase::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	return false;
}

const sgx_enclave_id_t EnclaveBase::GetEnclaveId() const
{
	return m_eid;
}

bool EnclaveBase::LoadToken(const fs::path& tokenPath, std::vector<uint8_t>& outToken)
{
	outToken.resize(sizeof(sgx_launch_token_t), 0);
	try
	{
		DiskFile tokenFile(tokenPath, FileBase::Mode::Read);
		tokenFile.ReadBlockExactSize(outToken);
		return true;
	}
	catch (const FileException&)
	{
		outToken.resize(sizeof(sgx_launch_token_t), 0);
		return false;
	}
}

bool EnclaveBase::UpdateToken(const fs::path& tokenPath, const std::vector<uint8_t>& inToken)
{
	try
	{
		WritableDiskFile tokenFile(tokenPath, WritableFileBase::WritableMode::Write);
		tokenFile.WriteBlockExactSize(inToken);
		return true;
	}
	catch (const FileException&)
	{
		return false;
	}
}

extern "C" int ocall_decent_sgx_ra_get_msg1(const uint64_t enclave_id, const uint32_t ra_ctx, sgx_ra_msg1_t* msg1)
{
	if (!msg1)
	{
		return false;
	}
	
	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::thread tmpThread([&enclaveRet, enclave_id, ra_ctx, msg1]() {
		enclaveRet = sgx_ra_get_msg1(ra_ctx, enclave_id, sgx_ra_get_ga, msg1);
	});
	tmpThread.join();

	return (enclaveRet == SGX_SUCCESS);
}

extern "C" size_t ocall_decent_sgx_ra_proc_msg2(const uint64_t enclave_id, const uint32_t ra_ctx, const sgx_ra_msg2_t* msg2, const size_t msg2_size, uint8_t** out_msg3)
{
	if (!msg2 || !out_msg3)
	{
		return 0;
	}

	*out_msg3 = nullptr;
	
	sgx_ra_msg3_t* tmpMsg3 = nullptr;
	uint32_t tmpMsg3Size = 0;
	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::thread tmpThread([&enclaveRet, enclave_id, ra_ctx, msg2, msg2_size, &tmpMsg3, &tmpMsg3Size]() {
		enclaveRet = sgx_ra_proc_msg2(ra_ctx, enclave_id, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted,
			msg2, static_cast<uint32_t>(msg2_size), &tmpMsg3, &tmpMsg3Size);
	});
	tmpThread.join();

	if (enclaveRet != SGX_SUCCESS)
	{
		return 0;
	}

	//Copy msg3 to our buffer pointer to avoid the mix use of malloc and delete[];
	*out_msg3 = new uint8_t[tmpMsg3Size];
	std::memcpy(*out_msg3, tmpMsg3, tmpMsg3Size);
	std::free(tmpMsg3);

	return tmpMsg3Size;
}

extern "C" int ocall_decent_sgx_ra_send_msg0s(void* const connection_ptr)
{
	try
	{
		sgx_ra_msg0s_t msg0s;
		sgx_status_t enclaveRet = sgx_get_extended_epid_group_id(&msg0s.extended_grp_id);
		if (enclaveRet != SGX_SUCCESS)
		{
			return false;
		}

		return StatConnection::SendPack(connection_ptr, &msg0s, sizeof(msg0s));
	}
	catch (const std::exception&)
	{
		return false;
	}
}
