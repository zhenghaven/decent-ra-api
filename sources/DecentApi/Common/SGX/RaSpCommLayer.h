#pragma once

#include <memory>

#include "../Net/AesGcmCommLayer.h"

typedef struct _sgx_ias_report_t sgx_ias_report_t;

namespace Decent
{
	namespace Sgx
	{
		class RaProcessorSp;

		class RaSpCommLayer : public Decent::Net::AesGcmCommLayer
		{
		public:
			RaSpCommLayer() = delete;
			RaSpCommLayer(Net::ConnectionBase& cnt, std::unique_ptr<RaProcessorSp>& raProcessor);
			RaSpCommLayer(const RaSpCommLayer& other) = delete;
			RaSpCommLayer(RaSpCommLayer&& other);

			const sgx_ias_report_t& GetIasReport() const;

			virtual ~RaSpCommLayer();

			virtual operator bool() const override;

		private:
			RaSpCommLayer(std::pair<std::unique_ptr<RaProcessorSp>, Net::ConnectionBase*> raProcessor);

			bool m_isHandShaked;
			std::unique_ptr<sgx_ias_report_t> m_iasReport;

		};
	}
}
