#pragma once

#include <memory>

#include "../../Common/Net/AesGcmCommLayer.h"

typedef struct _sgx_ias_report_t sgx_ias_report_t;

namespace Decent
{
	namespace Net
	{
		class EnclaveCntTranslator;
	}

	namespace Sgx
	{
		class RaProcessorClient;

		class RaClientCommLayer : public Decent::Net::AesGcmCommLayer
		{
		public:
			RaClientCommLayer() = delete;
			RaClientCommLayer(Decent::Net::EnclaveCntTranslator& connectionPtr, std::unique_ptr<Sgx::RaProcessorClient>& raProcessor);
			RaClientCommLayer(const RaClientCommLayer& other) = delete;
			RaClientCommLayer(RaClientCommLayer&& other);

			const sgx_ias_report_t& GetIasReport() const;

			virtual ~RaClientCommLayer();

			virtual operator bool() const override;

		private:
			RaClientCommLayer(std::pair<std::unique_ptr<RaProcessorClient>, Net::ConnectionBase*> raProcessor);

			bool m_isHandShaked;
			//std::unique_ptr<SgxRaProcessorClient> m_raProcessor;
			std::unique_ptr<sgx_ias_report_t> m_iasReport;

		};
	}
}
