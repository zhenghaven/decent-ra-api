#include "DecentApp.h"

#include <sgx_tcrypto.h>
#include <sgx_report.h>

#include "../Common/Tools/DataCoding.h"
#include "../Common/SGX/RuntimeError.h"
#include "../Common/Ra/RequestCategory.h"
#include "../Common/Net/ConnectionBase.h"

#include "../CommonApp/Base/EnclaveException.h"

#include "edl_decent_ra_app.h"

using namespace Decent::RaSgx;
using namespace Decent::Tools;
using namespace Decent::Net;

DecentApp::DecentApp(const std::string & enclavePath, const std::string & tokenPath, const std::string & wListKey, ConnectionBase & serverConn) :
	Sgx::EnclaveBase(enclavePath, tokenPath)
{
	InitEnclave(wListKey, serverConn);
}

DecentApp::DecentApp(const fs::path & enclavePath, const fs::path & tokenPath, const std::string & wListKey, ConnectionBase & serverConn) :
	Sgx::EnclaveBase(enclavePath, tokenPath)
{
	InitEnclave(wListKey, serverConn);
}

DecentApp::DecentApp(const std::string & enclavePath, const std::string & tokenPath, 
	const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep, 
	const std::string & wListKey, ConnectionBase & serverConn) :
	Sgx::EnclaveBase(enclavePath, tokenPath, numTWorker, numUWorker, retryFallback, retrySleep)
{
	InitEnclave(wListKey, serverConn);
}

DecentApp::DecentApp(const fs::path & enclavePath, const fs::path & tokenPath, 
	const size_t numTWorker, const size_t numUWorker, const size_t retryFallback, const size_t retrySleep, 
	const std::string & wListKey, ConnectionBase & serverConn) :
	Sgx::EnclaveBase(enclavePath, tokenPath, numTWorker, numUWorker, retryFallback, retrySleep)
{
	InitEnclave(wListKey, serverConn);
}

DecentApp::~DecentApp()
{
}

std::string DecentApp::GetAppX509Cert()
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	size_t certLen = 0;
	std::string retReport(5000, '\0');

	enclaveRet = ecall_decent_ra_app_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
	DECENT_CHECK_SGX_STATUS_ERROR(enclaveRet, ecall_decent_ra_app_get_x509_pem);
	DECENT_ASSERT_ENCLAVE_APP_RESULT(certLen > 0, "get Decent App's certificate.");

	if (certLen > retReport.size())
	{
		retReport.resize(certLen);

		enclaveRet = ecall_decent_ra_app_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
		DECENT_CHECK_SGX_STATUS_ERROR(enclaveRet, ecall_decent_ra_app_get_x509_pem);
		DECENT_ASSERT_ENCLAVE_APP_RESULT(certLen > 0, "get Decent App's certificate.");
	}

	return retReport;
}

bool DecentApp::ProcessSmartMessage(const std::string & category, ConnectionBase& connection, ConnectionBase*& freeHeldCnt)
{
	return false;
}

bool DecentApp::InitEnclave(const std::string & wListKey, ConnectionBase & serverConn)
{
	serverConn.SendContainer(Ra::RequestCategory::sk_requestAppCert);
	serverConn.SendContainer(wListKey); //Send request.

	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_decent_ra_app_init(GetEnclaveId(), &retval, &serverConn); //Get X509 Cert.
	DECENT_CHECK_SGX_STATUS_ERROR(enclaveRet, ecall_decent_app_init);
	DECENT_CHECK_SGX_STATUS_ERROR(retval, ecall_decent_app_init);
	
	return true;
}
