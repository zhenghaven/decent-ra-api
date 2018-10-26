#include "SgxRaSpCommLayer.h"

#include <sgx_key_exchange.h>

#include "../Connection.h"

#include "sgx_structs.h"

#include "SgxRaProcessorSp.h"

static std::unique_ptr<SgxRaProcessorSp> DoHandShake(void* const connectionPtr, std::unique_ptr<SgxRaProcessorSp>& raProcessor)
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

SgxRaSpCommLayer::SgxRaSpCommLayer(void * const connectionPtr, std::unique_ptr<SgxRaProcessorSp>& raProcessor) :
	SgxRaSpCommLayer(DoHandShake(connectionPtr, raProcessor))
{
}

SgxRaSpCommLayer::SgxRaSpCommLayer(SgxRaSpCommLayer && other) :
	AESGCMCommLayer(std::forward<AESGCMCommLayer>(other)),
	m_isHandShaked(other.m_isHandShaked),
	m_iasReport(std::move(other.m_iasReport))
{
	other.m_isHandShaked = false;
}

const sgx_ias_report_t & SgxRaSpCommLayer::GetIasReport() const
{
	return *m_iasReport;
}

SgxRaSpCommLayer::~SgxRaSpCommLayer()
{
}

SgxRaSpCommLayer::operator bool() const
{
	return AESGCMCommLayer::operator bool() && m_isHandShaked;
}

SgxRaSpCommLayer::SgxRaSpCommLayer(std::unique_ptr<SgxRaProcessorSp> raProcessor) :
	AESGCMCommLayer(raProcessor && raProcessor->IsAttested() ? raProcessor->GetSK() : General128BitKey()),
	m_isHandShaked(raProcessor && raProcessor->IsAttested()),
	m_iasReport(m_isHandShaked ? raProcessor->ReleaseIasReport() : new sgx_ias_report_t)
{
}
