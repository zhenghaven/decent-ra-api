#pragma once

#include <memory>

#include "../AESGCMCommLayer.h"

typedef struct _sgx_ias_report_t sgx_ias_report_t;

namespace Sgx
{
	class RaProcessorSp;

	class RaSpCommLayer : public AESGCMCommLayer
	{
	public:
		RaSpCommLayer() = delete;
		RaSpCommLayer(void* const connectionPtr, std::unique_ptr<RaProcessorSp>& raProcessor);
		RaSpCommLayer(const RaSpCommLayer& other) = delete;
		RaSpCommLayer(RaSpCommLayer&& other);

		const sgx_ias_report_t& GetIasReport() const;

		virtual ~RaSpCommLayer();

		virtual operator bool() const override;

	private:
		RaSpCommLayer(std::unique_ptr<RaProcessorSp> raProcessor);

		bool m_isHandShaked;
		std::unique_ptr<sgx_ias_report_t> m_iasReport;

	};
}
