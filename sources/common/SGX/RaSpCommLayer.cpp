#include "RaSpCommLayer.h"

#include <sgx_key_exchange.h>

#include "../Connection.h"

#include "sgx_structs.h"
#include "RaProcessorSp.h"

using namespace Sgx;

static std::unique_ptr<RaProcessorSp> DoHandShake(void* const connectionPtr, std::unique_ptr<RaProcessorSp>& raProcessor)
{
	if (!connectionPtr || !raProcessor ||
		!raProcessor->Init())
	{
		return nullptr;
	}

	std::string buf1;

	sgx_ra_msg0r_t msg0r;
	std::vector<uint8_t> msg2;
	sgx_ra_msg4_t msg4;

	if (!StaticConnection::ReceivePack(connectionPtr, buf1) ||
		buf1.size() != sizeof(sgx_ra_msg0s_t) ||
		!raProcessor->ProcessMsg0(*reinterpret_cast<const sgx_ra_msg0s_t*>(buf1.data()), msg0r) ||
		!StaticConnection::SendAndReceivePack(connectionPtr, &msg0r, sizeof(msg0r), buf1) ||
		buf1.size() != sizeof(sgx_ra_msg1_t) ||
		!raProcessor->ProcessMsg1(*reinterpret_cast<const sgx_ra_msg1_t*>(buf1.data()), msg2) ||
		!StaticConnection::SendAndReceivePack(connectionPtr, msg2.data(), msg2.size(), buf1) ||
		buf1.size() < sizeof(sgx_ra_msg3_t) ||
		!raProcessor->ProcessMsg3(*reinterpret_cast<const sgx_ra_msg3_t*>(buf1.data()), buf1.size(), msg4, nullptr) ||
		!StaticConnection::SendPack(connectionPtr, &msg4, sizeof(msg4)) )
	{
		return nullptr;
	}

	return std::move(raProcessor);
}

RaSpCommLayer::RaSpCommLayer(void * const connectionPtr, std::unique_ptr<RaProcessorSp>& raProcessor) :
	RaSpCommLayer(DoHandShake(connectionPtr, raProcessor))
{
}

RaSpCommLayer::RaSpCommLayer(RaSpCommLayer && other) :
	AESGCMCommLayer(std::forward<AESGCMCommLayer>(other)),
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
	return AESGCMCommLayer::operator bool() && m_isHandShaked;
}

RaSpCommLayer::RaSpCommLayer(std::unique_ptr<RaProcessorSp> raProcessor) :
	AESGCMCommLayer(raProcessor && raProcessor->IsAttested() ? raProcessor->GetSK() : General128BitKey()),
	m_isHandShaked(raProcessor && raProcessor->IsAttested()),
	m_iasReport(m_isHandShaked ? raProcessor->ReleaseIasReport() : new sgx_ias_report_t)
{
}
