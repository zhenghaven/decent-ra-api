#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#include "DecentApp.h"

#include <sgx_tcrypto.h>
#include <sgx_report.h>

#include "../../common/DataCoding.h"
#include "../Decent/Messages.h"
#include "../WhiteList/Requester.h"
#include "../Networking/Connection.h"
#include "../SGX/EnclaveRuntimeException.h"

#include <Enclave_u.h>

DecentSgx::DecentApp::DecentApp(const std::string & enclavePath, const std::string & tokenPath, const std::string & wListKey, Connection & serverConn) :
	Sgx::EnclaveBase(enclavePath, tokenPath)
{
	InitEnclave(wListKey, serverConn);
}

DecentSgx::DecentApp::DecentApp(const fs::path & enclavePath, const fs::path & tokenPath, const std::string & wListKey, Connection & serverConn) :
	Sgx::EnclaveBase(enclavePath, tokenPath)
{
	InitEnclave(wListKey, serverConn);
}

DecentSgx::DecentApp::DecentApp(const std::string & enclavePath, const KnownFolderType tokenLocType, const std::string & tokenFileName, const std::string & wListKey, Connection & serverConn) :
	Sgx::EnclaveBase(enclavePath, tokenLocType, tokenFileName)
{
	InitEnclave(wListKey, serverConn);
}

DecentSgx::DecentApp::~DecentApp()
{
}

bool DecentSgx::DecentApp::GetX509FromServer(const std::string & decentId, Connection& connection)
{
	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;

	size_t certLen = 0;
	std::string retReport(5000, '\0');

	enclaveRet = ecall_decent_app_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_get_x509_pem);

	if (certLen > retReport.size())
	{
		retReport.resize(certLen);

		enclaveRet = ecall_decent_app_get_x509_pem(GetEnclaveId(), &certLen, &retReport[0], retReport.size());
		CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_get_x509_pem);
	}

	retReport.resize(certLen);

	return retval == SGX_SUCCESS;
}

const std::string & DecentSgx::DecentApp::GetAppCert() const
{
	return m_appCert;
}

bool DecentSgx::DecentApp::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, Connection& connection)
{
	return false;
}

bool DecentSgx::DecentApp::InitEnclave(const std::string & wListKey, Connection & serverConn)
{
	using namespace Decent::Message;

	serverConn.SendPack(RequestAppCert(wListKey)); //Send request.

	sgx_status_t enclaveRet = SGX_SUCCESS;
	sgx_status_t retval = SGX_SUCCESS;
	enclaveRet = ecall_decent_app_init(GetEnclaveId(), &retval, &serverConn); //Get X509 Cert.
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(enclaveRet, ecall_decent_app_init);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, ecall_decent_app_init);
	
	return true;
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
