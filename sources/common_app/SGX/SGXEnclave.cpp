#include "SGXEnclave.h"

#include <algorithm>

#include <sgx_urts.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>

#include <boost/filesystem/operations.hpp>

#include "../Common.h"

#include "../Networking/Connection.h"

#include "../../common/DataCoding.h"
#include "../../common/SGX/sgx_ra_msg4.h"

#include "SGXClientRASession.h"
#include "SGXEnclaveRuntimeException.h"

#include <Enclave_u.h>

using namespace boost::asio;

static void CheckFilePath(const fs::path& enclavePath, const fs::path& tokenPath)
{
	if (!fs::exists(enclavePath))
	{
		throw SGXEnclaveRuntimeException(SGX_ERROR_INVALID_PARAMETER, "Enclave program file doesn't exist!");
	}
	if (!fs::exists(tokenPath.parent_path()))
	{
		fs::create_directories(tokenPath.parent_path());
	}
}

sgx_enclave_id_t SGXEnclave::LaunchEnclave(const fs::path& enclavePath, const fs::path& tokenPath)
{
	CheckFilePath(enclavePath, tokenPath);

	sgx_enclave_id_t outEnclaveID;
	
	int needUpdateToken = 0;
	std::vector<uint8_t> tokenBuf(sizeof(sgx_launch_token_t), 0);
	if (!SGXEnclave::LoadToken(tokenPath, tokenBuf))
	{
		LOGW("Enclave App - %s, Read token from %s Failed!", enclavePath.string().c_str(), tokenPath.string().c_str());
	}

	LOGI("SGX Enclave Token: \n%s\n\n", SerializeStruct(tokenBuf.data(), sizeof(sgx_launch_token_t)).c_str());
	sgx_status_t enclaveRet = sgx_create_enclave(enclavePath.string().c_str(), SGX_DEBUG_FLAG, reinterpret_cast<sgx_launch_token_t*>(tokenBuf.data()), &needUpdateToken, &outEnclaveID, NULL);
	if (enclaveRet != SGX_SUCCESS)
	{
		throw SGXEnclaveRuntimeException(enclaveRet, "sgx_create_enclave");
	}

	if (needUpdateToken)
	{
		LOGI("SGX Enclave Token (Updated): \n%s\n\n", SerializeStruct(tokenBuf.data(), sizeof(sgx_launch_token_t)).c_str());
		if (!SGXEnclave::UpdateToken(tokenPath, tokenBuf))
		{
			LOGW("Enclave App - %s, Write token to %s Failed!", enclavePath.string().c_str(), tokenPath.string().c_str());
		}
	}

	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_sgx_ra_client_init(outEnclaveID, &retval);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_init_ra_client_environment);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_init_ra_client_environment);

	return outEnclaveID;
}

SGXEnclave::SGXEnclave(const std::string& enclavePath, const std::string& tokenPath) :
	SGXEnclave(fs::path(enclavePath), fs::path(tokenPath))
{
	
}

SGXEnclave::SGXEnclave(const fs::path& enclavePath, const fs::path& tokenPath) :
	m_eid(SGXEnclave::LaunchEnclave(enclavePath, tokenPath)),
	m_enclavePath(enclavePath),
	m_tokenPath(tokenPath)
{
}

SGXEnclave::SGXEnclave(const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName) :
	SGXEnclave(fs::path(enclavePath), GetKnownFolderPath(tokenLocType).append(tokenFileName))
{
}

SGXEnclave::~SGXEnclave()
{
	ecall_sgx_ra_client_terminate(m_eid);
	sgx_destroy_enclave(m_eid);
}

void SGXEnclave::GetRAClientSignPubKey(sgx_ec256_public_t & outKey)
{
	sgx_status_t retval = SGX_SUCCESS;

	sgx_status_t enclaveRet = ecall_get_ra_client_pub_sig_key(GetEnclaveId(), &retval, &outKey);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_get_ra_client_pub_sig_key);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_get_ra_client_pub_sig_key);
}

std::shared_ptr<ClientRASession> SGXEnclave::GetRASession(std::unique_ptr<Connection>& connection)
{
	return std::make_shared<SGXClientRASession>(connection, *this);
}

uint32_t SGXEnclave::GetExGroupID()
{
	uint32_t res = 0;
	sgx_status_t enclaveRet = sgx_get_extended_epid_group_id(&res);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, sgx_get_extended_epid_group_id);

	return res;
}

sgx_status_t SGXEnclave::ProcessRAMsg0Resp(const std::string & ServerID, const sgx_ec256_public_t & inKey, int enablePSE, sgx_ra_context_t & outContextID, sgx_ra_msg1_t & outMsg1)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_process_ra_msg0_resp(GetEnclaveId(), &retval, ServerID.c_str(), &inKey, enablePSE, &outContextID);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg0_resp);
	if (retval != SGX_SUCCESS)
	{
		return retval;
	}

	enclaveRet = sgx_ra_get_msg1(outContextID, GetEnclaveId(), sgx_ra_get_ga, &outMsg1);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, sgx_ra_get_msg1);

	return SGX_SUCCESS;
}

sgx_status_t SGXEnclave::ProcessRAMsg2(const std::string & ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t & inContextID)
{
	return SGXEnclave::ProcessRAMsg2(ServerID, inMsg2, outMsg3, inContextID, sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted);
}

sgx_status_t SGXEnclave::ProcessRAMsg2(const std::string & ServerID, const std::vector<uint8_t>& inMsg2, std::vector<uint8_t>& outMsg3, sgx_ra_context_t & inContextID, sgx_ecall_proc_msg2_trusted_t proc_msg2_func, sgx_ecall_get_msg3_trusted_t get_msg3_func)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	const sgx_ra_msg2_t& msg2Ref = *reinterpret_cast<const sgx_ra_msg2_t*>(inMsg2.data());
	sgx_ra_msg3_t* outMsg3ptr = nullptr;
	uint32_t msg3Size = 0;

	retval = sgx_ra_proc_msg2(inContextID, GetEnclaveId(), proc_msg2_func, get_msg3_func, &msg2Ref, static_cast<uint32_t>(inMsg2.size()), &outMsg3ptr, &msg3Size);
	if (retval != SGX_SUCCESS)
	{
		return retval;
	}
	//TODO: make sure if we really need to check this.
	if (msg3Size == 0 || msg3Size <= sizeof(sgx_ra_msg3_t))
	{
		return SGX_ERROR_UNEXPECTED;
	}

	std::vector<uint8_t> tmpMsg3(reinterpret_cast<uint8_t*>(outMsg3ptr), reinterpret_cast<uint8_t*>(outMsg3ptr) + msg3Size);
	outMsg3.swap(tmpMsg3);

	std::free(outMsg3ptr);

	enclaveRet = ecall_process_ra_msg2(GetEnclaveId(), &retval, ServerID.c_str(), &(msg2Ref.g_b), inContextID);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg2);

	return retval;
}

sgx_status_t SGXEnclave::ProcessRAMsg4(const std::string & ServerID, const sgx_ra_msg4_t & inMsg4, const sgx_ec256_signature_t & inMsg4Sign, sgx_ra_context_t inContextID)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	//const sgx_quote_t* quotePtr = reinterpret_cast<const sgx_quote_t*>(&(inMsg3.quote));
	enclaveRet = ecall_process_ra_msg4(GetEnclaveId(), &retval, ServerID.c_str(), &inMsg4, const_cast<sgx_ec256_signature_t*>(&inMsg4Sign), inContextID);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_process_ra_msg4);

	return retval;
}

const sgx_enclave_id_t SGXEnclave::GetEnclaveId() const
{
	return m_eid;
}

bool SGXEnclave::LoadToken(const fs::path& tokenPath, std::vector<uint8_t>& outToken)
{
	FileHandler tokenFile(tokenPath, FileHandler::Mode::Read);
	if (!tokenFile.Open())
	{
		return false;
	}
	bool readRes = tokenFile.ReadBlock(outToken, sizeof(sgx_launch_token_t));
	if (!readRes)
	{
		outToken.resize(sizeof(sgx_launch_token_t), 0);
	}
	return readRes;
}

bool SGXEnclave::UpdateToken(const fs::path& tokenPath, const std::vector<uint8_t>& inToken)
{
	FileHandler tokenFile(tokenPath, FileHandler::Mode::Write);
	if (!tokenFile.Open())
	{
		return false;
	}
	bool writeRes = tokenFile.WriteBlock(inToken);
	return writeRes;
}
