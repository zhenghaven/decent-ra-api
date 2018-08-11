#include "SGXServiceProvider.h"

#include "../../common/SGX/SGXRAServiceProvider.h"
#include "../../common/SGX/sgx_constants.h"

#include "SGXServiceProviderRASession.h"
#include "SGXEnclaveRuntimeException.h"

SGXServiceProvider::SGXServiceProvider(IASConnector ias) :
	m_ias(ias)
{
}

SGXServiceProvider::~SGXServiceProvider()
{
}
//
//std::string SGXServiceProvider::GetRASenderID() const
//{
//	return m_raSenderID;
//}

std::shared_ptr<ServiceProviderRASession> SGXServiceProvider::GetRASession(std::unique_ptr<Connection>& connection)
{
	return std::make_shared<SGXServiceProviderRASession>(connection, *this, m_ias);
}

void SGXServiceProvider::GetRASPSignPubKey(sgx_ec256_public_t & outKey)
{
	sgx_status_t retval = SGXRAEnclave::GetRASPSignPubKey(&outKey);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, SGXRAEnclave::GetRASPSignPubKey);
}

sgx_status_t SGXServiceProvider::GetRASPEncrPubKey(sgx_ec256_public_t & outKey)
{
	return SGXRAEnclave::GetRASPEncrPubKey(0, &outKey);
}

void SGXServiceProvider::InitSPRAEnvironment()
{
	sgx_status_t retval = SGXRAEnclave::InitRaSpEnvironment();
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, SGXRAEnclave::InitRaSpEnvironment);
}

sgx_status_t SGXServiceProvider::GetIasReportNonce(const std::string & clientID, std::string & outNonce)
{
	outNonce.resize(IAS_REQUEST_NONCE_SIZE);
	sgx_status_t retval = SGXRAEnclave::GetIasNonce(clientID.c_str(), &outNonce[0]);
	return retval;
}

sgx_status_t SGXServiceProvider::ProcessRAMsg0Send(const std::string & clientID)
{
	sgx_status_t retval = SGX_SUCCESS;
	retval = SGXRAEnclave::ProcessRaMsg0Send(clientID.c_str());

	return retval;
}

sgx_status_t SGXServiceProvider::ProcessRAMsg1(const std::string & clientID, const sgx_ra_msg1_t & inMsg1, sgx_ra_msg2_t & outMsg2)
{
	sgx_status_t retval = SGX_SUCCESS;
	retval = SGXRAEnclave::ProcessRaMsg1(clientID.c_str(), &inMsg1, &outMsg2);

	return retval;
}

sgx_status_t SGXServiceProvider::ProcessRAMsg3(const std::string & clientID, const sgx_ra_msg3_t & inMsg3, const uint32_t msg3Len, const std::string & iasReport, const std::string & reportSign, const std::string & reportCertChain, sgx_ra_msg4_t & outMsg4, sgx_ec256_signature_t & outMsg4Sign)
{
	sgx_status_t retval = SGX_SUCCESS;
	retval = SGXRAEnclave::ProcessRaMsg3(clientID.c_str(), reinterpret_cast<const uint8_t*>(&inMsg3), msg3Len, iasReport.c_str(), reportSign.c_str(), reportCertChain.c_str(), &outMsg4, &outMsg4Sign);

	return retval;
}
