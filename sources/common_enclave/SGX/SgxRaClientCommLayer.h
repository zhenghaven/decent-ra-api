#pragma once

#include <memory>

#include "../../common/AESGCMCommLayer.h"

typedef struct _sgx_ias_report_t sgx_ias_report_t;

class SgxRaProcessorClient;

class SgxRaClientCommLayer : public AESGCMCommLayer
{
public:
	SgxRaClientCommLayer() = delete;
	SgxRaClientCommLayer(void* const connectionPtr, std::unique_ptr<SgxRaProcessorClient>& raProcessor);
	SgxRaClientCommLayer(const SgxRaClientCommLayer& other) = delete;
	SgxRaClientCommLayer(SgxRaClientCommLayer&& other);

	const sgx_ias_report_t& GetIasReport() const;

	virtual ~SgxRaClientCommLayer();

	virtual operator bool() const override;

private:
	SgxRaClientCommLayer(std::unique_ptr<SgxRaProcessorClient> raProcessor);

	bool m_isHandShaked;
	//std::unique_ptr<SgxRaProcessorClient> m_raProcessor;
	std::unique_ptr<sgx_ias_report_t> m_iasReport;

};
