#pragma once

#include "../ServiceProviderBase.h"

#include <vector>
#include <string>

#include <sgx_error.h>

#include "IAS/IASConnector.h"

typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _ra_msg3_t sgx_ra_msg3_t;
typedef struct _ra_msg4_t sgx_ra_msg4_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;
typedef struct _sgx_report_data_t sgx_report_data_t;

class SGXServiceProvider : public ServiceProviderBase
{
public:
	SGXServiceProvider() = delete;

	SGXServiceProvider(IASConnector ias);

	virtual ~SGXServiceProvider();

	virtual std::shared_ptr<ServiceProviderRASession> GetRASession(std::unique_ptr<Connection>& connection) override;

	virtual void GetRASPSignPubKey(sgx_ec256_public_t& outKey) override;
	virtual sgx_status_t GetIasReportNonce(const std::string & clientID, std::string& outNonce);
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID);
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2);
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const std::vector<uint8_t> & inMsg3, const std::string& iasReport, const std::string& reportSign, const std::string& reportCertChain, sgx_ra_msg4_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign, sgx_report_data_t* outOriRD = nullptr);

protected:
	const IASConnector m_ias;
};
