#include "RaSpCommLayer.h"

#include <sgx_key_exchange.h>

#include "../Net/ConnectionBase.h"
#include "../Net/NetworkException.h"

#include "sgx_structs.h"
#include "RaProcessorSp.h"

using namespace Decent::Net;
using namespace Decent::Sgx;

static std::unique_ptr<RaProcessorSp> DoHandShake(ConnectionBase& cnt, std::unique_ptr<RaProcessorSp>& raProcessor)
{
	if (!raProcessor ||
		!raProcessor->Init())
	{
		throw Exception("Null pointer is given to the RA Processor SP DoHandShake.");
	}

	std::string buf1;

	sgx_ra_msg0r_t msg0r;
	std::vector<uint8_t> msg2;
	sgx_ra_msg4_t msg4;

	cnt.ReceivePack(buf1);
	if (buf1.size() != sizeof(sgx_ra_msg0s_t) ||
		!raProcessor->ProcessMsg0(*reinterpret_cast<const sgx_ra_msg0s_t*>(buf1.data()), msg0r))
	{
		throw Exception("Decent::Sgx::RaProcessorSp DoHandShake Failed.");
	}

	cnt.SendAndReceivePack(&msg0r, sizeof(msg0r), buf1);
	if (buf1.size() != sizeof(sgx_ra_msg1_t) ||
		!raProcessor->ProcessMsg1(*reinterpret_cast<const sgx_ra_msg1_t*>(buf1.data()), msg2))
	{
		throw Exception("Decent::Sgx::RaProcessorSp DoHandShake Failed.");
	}

	cnt.SendAndReceivePack(msg2.data(), msg2.size(), buf1);
	if (buf1.size() < sizeof(sgx_ra_msg3_t) ||
		!raProcessor->ProcessMsg3(*reinterpret_cast<const sgx_ra_msg3_t*>(buf1.data()), buf1.size(), msg4, nullptr))
	{
		throw Exception("Decent::Sgx::RaProcessorSp DoHandShake Failed.");
	}

	cnt.SendPack(&msg4, sizeof(msg4));

	return std::move(raProcessor);
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

RaSpCommLayer::RaSpCommLayer(std::unique_ptr<RaProcessorSp> raProcessor) :
	AesGcmCommLayer(raProcessor && raProcessor->IsAttested() ? raProcessor->GetSK() : General128BitKey()),
	m_isHandShaked(raProcessor && raProcessor->IsAttested()),
	m_iasReport(m_isHandShaked ? raProcessor->ReleaseIasReport() : new sgx_ias_report_t)
{
}
