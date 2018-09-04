#include "SGXServiceProvider.h"

#include <sgx_tcrypto.h>

#include "../../common/DataCoding.h"
#include "../../common/SGX/SGXRAServiceProvider.h"
#include "../../common/SGX/sgx_constants.h"

#include "SGXMessages/SGXRAMessage.h"
#include "SGXEnclaveRuntimeException.h"
#include "SGXServiceProviderRASession.h"
#include "IAS/IASConnector.h"

SGXServiceProvider::SGXServiceProvider(const std::shared_ptr<IASConnector>& ias) :
	m_ias(ias)
{
	sgx_status_t retval = SGXRAEnclave::ServiceProviderInit();
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, SGXRAEnclave::InitRaSpEnvironment);
}

SGXServiceProvider::~SGXServiceProvider()
{
	SGXRAEnclave::ServiceProviderTerminate();
}

const char * SGXServiceProvider::GetPlatformType() const
{
	return SGXServiceProviderBase::sk_platformType;
}

std::shared_ptr<ServiceProviderRASession> SGXServiceProvider::GetRASPSession(std::unique_ptr<Connection>& connection)
{
	return std::make_shared<SGXServiceProviderRASession>(connection, *this, *m_ias);
}

void SGXServiceProvider::GetRASPSignPubKey(sgx_ec256_public_t & outKey) const
{
	sgx_status_t retval = SGXRAEnclave::GetRASPSignPubKey(outKey);
	CHECK_SGX_ENCLAVE_RUNTIME_EXCEPTION(retval, SGXRAEnclave::GetRASPSignPubKey);
}

const std::string SGXServiceProvider::GetRASPSignPubKey() const
{
	sgx_ec256_public_t signPubKey;
	GetRASPSignPubKey(signPubKey);
	return SerializePubKey(signPubKey);
}

sgx_status_t SGXServiceProvider::GetIasReportNonce(const std::string & clientID, std::string & outNonce)
{
	outNonce.resize(IAS_REQUEST_NONCE_SIZE);
	sgx_status_t retval = SGXRAEnclave::GetIasNonce(clientID.c_str(), &outNonce[0]);
	return retval;
}

sgx_status_t SGXServiceProvider::ProcessRAMsg1(const std::string & clientID, const sgx_ec256_public_t& inKey, const sgx_ra_msg1_t & inMsg1, sgx_ra_msg2_t & outMsg2)
{
	sgx_status_t retval = SGX_SUCCESS;
	retval = SGXRAEnclave::ProcessRaMsg1(clientID.c_str(), inKey, inMsg1, outMsg2);

	return retval;
}

sgx_status_t SGXServiceProvider::ProcessRAMsg3(const std::string & clientID, const std::vector<uint8_t> & inMsg3, const std::string & iasReport, const std::string & reportSign, const std::string & reportCertChain, sgx_ias_report_t & outMsg4, sgx_ec256_signature_t & outMsg4Sign, sgx_report_data_t* outOriRD)
{
	sgx_status_t retval = SGX_SUCCESS;
	retval = SGXRAEnclave::ProcessRaMsg3(clientID.c_str(), inMsg3.data(), static_cast<uint32_t>(inMsg3.size()), iasReport, reportSign, reportCertChain, outMsg4, outMsg4Sign, outOriRD);

	return retval;
}

bool SGXServiceProvider::ProcessSmartMessage(const std::string & category, const Json::Value & jsonMsg, std::unique_ptr<Connection>& connection)
{
	if (category == SGXRASPMessage::sk_ValueCat)
	{
		return SGXServiceProviderRASession::SmartMsgEntryPoint(connection, *this, *m_ias, jsonMsg);
	}
	else
	{
		return false;
	}
}
