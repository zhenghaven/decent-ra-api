#pragma once

#include "../ServiceProviderBase.h"

#include <sgx_error.h>

#include "IAS/IASConnector.h"

typedef struct _ra_msg1_t sgx_ra_msg1_t;
typedef struct _ra_msg2_t sgx_ra_msg2_t;
typedef struct _ra_msg3_t sgx_ra_msg3_t;
typedef struct _ra_msg4_t sgx_ra_msg4_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;

class SGXServiceProvider : public ServiceProviderBase
{
public:
	SGXServiceProvider() = delete;

	SGXServiceProvider(IASConnector ias);

	virtual ~SGXServiceProvider();

	//virtual std::string GetRASenderID() const override;
	virtual std::shared_ptr<ServiceProviderRASession> GetRASession(std::unique_ptr<Connection>& connection) override;

	virtual sgx_status_t InitSPEnvironment() = 0;
	virtual sgx_status_t ProcessRAMsg0Send(const std::string& clientID) = 0;
	virtual sgx_status_t ProcessRAMsg1(const std::string& clientID, const sgx_ra_msg1_t& inMsg1, sgx_ra_msg2_t& outMsg2) = 0;
	virtual sgx_status_t ProcessRAMsg3(const std::string& clientID, const sgx_ra_msg3_t& inMsg3, const uint32_t msg3Len, const std::string& iasReport, const std::string& reportSign, sgx_ra_msg4_t& outMsg4, sgx_ec256_signature_t& outMsg4Sign) = 0;

protected:
	//std::string m_raSenderID;

private:
	IASConnector m_ias;
};
