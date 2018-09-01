#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_APP_INTERNAL

#pragma once

#include "../DecentAppEnclave.h"
#include "SGXEnclaveServiceProvider.h"

#include <memory>

typedef struct _report_body_t sgx_report_body_t;
typedef struct _sgx_ec256_signature_t sgx_ec256_signature_t;

class SGXDecentAppEnclave : public SGXEnclaveServiceProvider, virtual public DecentAppEnclave
{
public:
	SGXDecentAppEnclave() = delete;
	
	using SGXEnclaveServiceProvider::SGXEnclaveServiceProvider;
	
	virtual ~SGXDecentAppEnclave();

	virtual bool ProcessDecentSelfRAReport(std::string& inReport) override;

	virtual bool SendReportDataToServer(const std::string& decentId, const std::unique_ptr<Connection>& connection) override;

	virtual bool ProcessAppReportSignMsg(const std::string& trustedMsg) override;

	virtual const std::string& GetDecentRAReport() const override;
	virtual const std::string& GetEnclaveReport() const override;
	virtual const std::string& GetEnclaveReportSign() const override;

private:
	std::string m_decentRAReport;
	std::string m_enclaveReport;
	std::string m_enclaveReportSign;

	std::unique_ptr<sgx_report_body_t> m_sgxEnclaveReport;
	std::unique_ptr<sgx_ec256_signature_t> m_sgxEnclaveReportSign;
};


#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL