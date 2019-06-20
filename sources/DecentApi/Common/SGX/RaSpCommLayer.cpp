#include "RaSpCommLayer.h"

#include <sgx_key_exchange.h>

#include "../Net/ConnectionBase.h"
#include "../Net/NetworkException.h"

#include "sgx_structs.h"
#include "RaProcessorSp.h"

using namespace Decent::Net;
using namespace Decent::Sgx;

static std::pair<std::unique_ptr<RaProcessorSp>, ConnectionBase*> DoHandShake(ConnectionBase& cnt, std::unique_ptr<RaProcessorSp>& raProcessor)
{
	if (!raProcessor)
	{
		throw Exception("Null pointer is given to the RA Processor SP DoHandShake.");
	}
	
	raProcessor->Init();

	sgx_ra_msg0s_t msg0s;
	sgx_ra_msg0r_t msg0r;
	sgx_ra_msg1_t msg1;
	std::vector<uint8_t> msg2;
	std::string msg3;
	sgx_ra_msg4_t msg4;

	cnt.ReceiveRawGuarantee(&msg0s, sizeof(msg0s));

	raProcessor->ProcessMsg0(msg0s, msg0r);

	cnt.SendRawGuarantee(&msg0r, sizeof(msg0r));
	cnt.ReceiveRawGuarantee(&msg1, sizeof(msg1));

	raProcessor->ProcessMsg1(msg1, msg2);

	cnt.SendAndReceivePack(msg2.data(), msg2.size(), msg3);
	if (msg3.size() < sizeof(sgx_ra_msg3_t))
	{
		throw Exception("Decent::Sgx::RaProcessorSp DoHandShake Failed.");
	}
	raProcessor->ProcessMsg3(*reinterpret_cast<const sgx_ra_msg3_t*>(msg3.data()), msg3.size(), msg4, nullptr);

	cnt.SendRawGuarantee(&msg4, sizeof(msg4));

	return std::make_pair(std::move(raProcessor), &cnt);
}

RaSpCommLayer::RaSpCommLayer(ConnectionBase& cnt, std::unique_ptr<RaProcessorSp>& raProcessor) :
	RaSpCommLayer(DoHandShake(cnt, raProcessor))
{
}

RaSpCommLayer::RaSpCommLayer(RaSpCommLayer && other) :
	AesGcmCommLayer(std::forward<AesGcmCommLayer>(other)),
	m_isHandShaked(other.m_isHandShaked),
	m_iasReport(std::move(other.m_iasReport))
{
	other.m_isHandShaked = false;
}

const sgx_ias_report_t & RaSpCommLayer::GetIasReport() const
{
	return *m_iasReport;
}

RaSpCommLayer::~RaSpCommLayer()
{
}

RaSpCommLayer::operator bool() const
{
	return AesGcmCommLayer::operator bool() && m_isHandShaked;
}

RaSpCommLayer::RaSpCommLayer(std::pair<std::unique_ptr<RaProcessorSp>, ConnectionBase*> raProcessor) :
	AesGcmCommLayer(raProcessor.first && raProcessor.first->IsAttested() ? raProcessor.first->GetSK() : General128BitKey(), raProcessor.second),
	m_isHandShaked(raProcessor.first && raProcessor.first->IsAttested()),
	m_iasReport(m_isHandShaked ? raProcessor.first->ReleaseIasReport() : new sgx_ias_report_t)
{
}
