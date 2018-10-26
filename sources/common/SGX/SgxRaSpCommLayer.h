#pragma once

#include <memory>

#include "../AESGCMCommLayer.h"

typedef struct _sgx_ias_report_t sgx_ias_report_t;

class SgxRaProcessorSp;

class SgxRaSpCommLayer : public AESGCMCommLayer
{
public:
	SgxRaSpCommLayer() = delete;
	SgxRaSpCommLayer(void* const connectionPtr, std::unique_ptr<SgxRaProcessorSp>& raProcessor);
	SgxRaSpCommLayer(const SgxRaSpCommLayer& other) = delete;
	SgxRaSpCommLayer(SgxRaSpCommLayer&& other);

	const sgx_ias_report_t& GetIasReport() const;

	virtual ~SgxRaSpCommLayer();

	virtual operator bool() const override;

private:
	SgxRaSpCommLayer(std::unique_ptr<SgxRaProcessorSp> raProcessor);

	bool m_isHandShaked;
	std::unique_ptr<sgx_ias_report_t> m_iasReport;

};
