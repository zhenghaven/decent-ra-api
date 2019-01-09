#include "../../common/ModuleConfigInternal.h"

#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#include "SGXDecentEnclave.h"

#include <thread>
#include <cstring>

#include <sgx_ukey_exchange.h>
#include <sgx_tcrypto.h>
#include <sgx_uae_service.h>

#include <Enclave_u.h>

#include "../common/DataCoding.h"

#include "../DecentMessages/DecentMessage.h"
#include "../DecentMessages/DecentAppMessage.h"
#include "../DecentAppLASession.h"
#include "../DecentRASession.h"

#include "SGXEnclaveRuntimeException.h"

static void InitDecent(sgx_enclave_id_t id, const sgx_spid_t& spid)
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decent_init(id, &retval, &spid);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_init);
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const std::string& tokenPath) :
	SGXEnclaveServiceProvider(ias, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
	m_selfRaReport = GenerateDecentSelfRAReport();
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const fs::path& enclavePath, const fs::path& tokenPath) :
	SGXEnclaveServiceProvider(ias, enclavePath, tokenPath)
{
	InitDecent(GetEnclaveId(), spid);
	m_selfRaReport = GenerateDecentSelfRAReport();
}

SGXDecentEnclave::SGXDecentEnclave(const sgx_spid_t& spid, const std::shared_ptr<IASConnector>& ias, const std::string& enclavePath, const KnownFolderType tokenLocType, const std::string& tokenFileName) :
	SGXEnclaveServiceProvider(ias, enclavePath, tokenLocType, tokenFileName)
{
	InitDecent(GetEnclaveId(), spid);
	m_selfRaReport = GenerateDecentSelfRAReport();
}

SGXDecentEnclave::~SGXDecentEnclave()
{
	ecall_decent_terminate(GetEnclaveId());
}

std::string SGXDecentEnclave::GetDecentSelfRAReport() const
{
	return m_selfRaReport;
}

bool SGXDecentEnclave::ProcessDecentSelfRAReport(const std::string & inReport)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	int retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_process_ias_ra_report(GetEnclaveId(), &retval, inReport.c_str());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_process_ias_ra_report);

	return retval != 0;
}

bool SGXDecentEnclave::ProcessAppX509Req(Connection& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	enclaveRet = ecall_decent_proc_app_x509_req(GetEnclaveId(), &retval, &connection);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_proc_app_x509_req);

	return retval == SGX_SUCCESS;
}

bool SGXDecentEnclave::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	if (category == DecentAppMessage::sk_ValueCat)
	{
		return DecentServerLASession::SmartMsgEntryPoint(connection, *this, *this, jsonMsg);
	}
	else
	{
		return false;
	}
}

std::string SGXDecentEnclave::GenerateDecentSelfRAReport()
{
	sgx_status_t retval = SGX_SUCCESS;
	sgx_status_t enclaveRet = ecall_decent_server_generate_x509(GetEnclaveId(), &retval, m_ias.get(), GetEnclaveId());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_generate_x509);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_server_generate_x509);

	size_t certLen = 0;

	enclaveRet = ecall_decent_server_get_x509_pem(GetEnclaveId(), &certLen, nullptr, 0);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_get_x509_pem);

	std::string retReport(certLen, '\0');
	
	enclaveRet = ecall_decent_server_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_server_get_x509_pem);

	return retReport;
}



#include <mutex>

static sgx_target_info_t g_qe_target_info;
static std::mutex g_ukey_mutex;
static std::unique_lock<std::mutex> g_ukey_spin_lock(g_ukey_mutex, std::defer_lock);

#ifndef ERROR_BREAK
#define ERROR_BREAK(x)  if(x){break;}
#endif
#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

sgx_status_t test_sgx_ra_get_msg1(
	sgx_ra_context_t context,
	sgx_enclave_id_t eid,
	sgx_ecall_get_ga_trusted_t p_get_ga,
	sgx_ra_msg1_t *p_msg1)
{
	if (!p_msg1 || !p_get_ga)
		return SGX_ERROR_INVALID_PARAMETER;
	sgx_epid_group_id_t gid = { 0 };
	sgx_target_info_t qe_target_info;

	memset(&qe_target_info, 0, sizeof(qe_target_info));
	sgx_status_t ret = sgx_init_quote(&qe_target_info, &gid);
	if (SGX_SUCCESS != ret)
		return ret;
	g_ukey_spin_lock.lock();
	if (memcpy_s(&g_qe_target_info, sizeof(g_qe_target_info),
		&qe_target_info, sizeof(qe_target_info)) != 0)
	{
		g_ukey_spin_lock.unlock();
		return SGX_ERROR_UNEXPECTED;
	}
	g_ukey_spin_lock.unlock();
	if (memcpy_s(&p_msg1->gid, sizeof(p_msg1->gid), &gid, sizeof(gid)) != 0)
		return SGX_ERROR_UNEXPECTED;
	sgx_ec256_public_t g_a;
	sgx_status_t status = SGX_ERROR_UNEXPECTED;
	memset(&g_a, 0, sizeof(g_a));
	ret = p_get_ga(eid, &status, context, &g_a);
	if (SGX_SUCCESS != ret)
		return ret;
	if (SGX_SUCCESS != status)
		return status;
	memcpy_s(&p_msg1->g_a, sizeof(p_msg1->g_a), &g_a, sizeof(g_a));
	return SGX_SUCCESS;
}

extern "C" int ocall_decent_ra_get_msg1(const uint64_t enclave_id, const uint32_t ra_ctx, sgx_ra_msg1_t* msg1)
{
	if (!msg1)
	{
		return false;
	}

	sgx_status_t enclaveRet = SGX_SUCCESS;
	std::thread tmpThread([&enclaveRet, enclave_id, ra_ctx, msg1]() {
		enclaveRet = test_sgx_ra_get_msg1(ra_ctx, enclave_id, decent_ra_get_ga, msg1);
	});
	tmpThread.join();

	return (enclaveRet == SGX_SUCCESS);
}



sgx_status_t test_sgx_ra_proc_msg2(
	sgx_ra_context_t context,
	sgx_enclave_id_t eid,
	sgx_ecall_proc_msg2_trusted_t p_proc_msg2,
	sgx_ecall_get_msg3_trusted_t p_get_msg3,
	const sgx_ra_msg2_t *p_msg2,
	uint32_t msg2_size,
	sgx_ra_msg3_t **pp_msg3,
	uint32_t *p_msg3_size)
{
	if (!p_msg2 || !p_proc_msg2 || !p_get_msg3 || !p_msg3_size || !pp_msg3)
		return SGX_ERROR_INVALID_PARAMETER;
	if (msg2_size != sizeof(sgx_ra_msg2_t) + p_msg2->sig_rl_size)
		return SGX_ERROR_INVALID_PARAMETER;

	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	sgx_report_t report;
	sgx_ra_msg3_t *p_msg3 = NULL;

	memset(&report, 0, sizeof(report));

	{
		sgx_quote_nonce_t nonce;
		sgx_report_t qe_report;
		sgx_target_info_t qe_target_info;

		memset(&nonce, 0, sizeof(nonce));
		memset(&qe_report, 0, sizeof(qe_report));

		sgx_status_t status;
		g_ukey_spin_lock.lock();
		if (memcpy_s(&qe_target_info, sizeof(qe_target_info),
			&g_qe_target_info, sizeof(g_qe_target_info)) != 0)
		{
			ret = SGX_ERROR_UNEXPECTED;
			g_ukey_spin_lock.unlock();
			goto CLEANUP;
		}
		g_ukey_spin_lock.unlock();
		ret = p_proc_msg2(eid, &status, context, p_msg2, &qe_target_info,
			&report, &nonce);
		if (SGX_SUCCESS != ret)
		{
			goto CLEANUP;
		}
		if (SGX_SUCCESS != status)
		{
			ret = status;
			goto CLEANUP;
		}
		report.body.mr_enclave.m[0] = 77;

		uint32_t quote_size = 0;
		ret = sgx_calc_quote_size(p_msg2->sig_rl_size ?
			const_cast<uint8_t *>(p_msg2->sig_rl) : NULL,
			p_msg2->sig_rl_size,
			&quote_size);
		if (SGX_SUCCESS != ret)
		{
			goto CLEANUP;
		}

		//check integer overflow of quote_size
		if (UINT32_MAX - quote_size < sizeof(sgx_ra_msg3_t))
		{
			ret = SGX_ERROR_UNEXPECTED;
			goto CLEANUP;
		}
		uint32_t msg3_size = static_cast<uint32_t>(sizeof(sgx_ra_msg3_t)) + quote_size;
		p_msg3 = (sgx_ra_msg3_t *)malloc(msg3_size);
		if (!p_msg3)
		{
			ret = SGX_ERROR_OUT_OF_MEMORY;
			goto CLEANUP;
		}
		memset(p_msg3, 0, msg3_size);

		ret = sgx_get_quote(&report,
			p_msg2->quote_type == SGX_UNLINKABLE_SIGNATURE ?
			SGX_UNLINKABLE_SIGNATURE : SGX_LINKABLE_SIGNATURE,
			const_cast<sgx_spid_t *>(&p_msg2->spid),
			&nonce,
			p_msg2->sig_rl_size ?
			const_cast<uint8_t *>(p_msg2->sig_rl) : NULL,
			p_msg2->sig_rl_size,
			&qe_report,
			(sgx_quote_t *)p_msg3->quote,
			quote_size);
		if (SGX_SUCCESS != ret)
		{
			goto CLEANUP;
		}

		ret = p_get_msg3(eid, &status, context, quote_size, &qe_report,
			p_msg3, msg3_size);
		if (SGX_SUCCESS != ret)
		{
			goto CLEANUP;
		}
		if (SGX_SUCCESS != status)
		{
			ret = status;
			goto CLEANUP;
		}
		*pp_msg3 = p_msg3;
		*p_msg3_size = msg3_size;
	}

CLEANUP:
	if (ret)
		SAFE_FREE(p_msg3);
	return ret;
}

extern "C" size_t ocall_decent_ra_proc_msg2(const uint64_t enclave_id, const uint32_t ra_ctx, const sgx_ra_msg2_t* msg2, const size_t msg2_size, uint8_t** out_msg3)
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
		enclaveRet = test_sgx_ra_proc_msg2(ra_ctx, enclave_id, decent_ra_proc_msg2_trusted, decent_ra_get_msg3_trusted,
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

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
