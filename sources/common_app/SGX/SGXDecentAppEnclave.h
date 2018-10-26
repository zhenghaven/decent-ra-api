#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#pragma once

#include "../DecentAppEnclave.h"
#include "SGXEnclave.h"

#include <memory>

typedef struct _report_body_t sgx_report_body_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;

class SGXDecentAppEnclave : public SGXEnclave, virtual public DecentAppEnclave
{
public:
	SGXDecentAppEnclave() = delete;
	
	using SGXEnclave::SGXEnclave;
	
	virtual ~SGXDecentAppEnclave();

	virtual bool ProcessDecentSelfRAReport(std::string& inReport) override;
	virtual bool ProcessDecentSelfRAReport(const std::string& inReport) override;

	virtual bool GetX509FromServer(const std::string& decentId, Connection& connection) override;

	virtual const std::string& GetDecentRAReport() const override;
	virtual const std::string& GetAppCert() const override;

	virtual bool ProcessSmartMessage(const std::string& category, const Json::Value& jsonMsg, Connection& connection) override;

private:
	std::string m_decentRAReport;
	std::string m_appCert;
};

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
