#include "RaClientCommLayer.h"

#include <Enclave_t.h>

#include "../../common/Connection.h"
#include "../../common/SGX/sgx_structs.h"

#include "RaProcessorClient.h"

using namespace Sgx;

static std::unique_ptr<Sgx::RaProcessorClient> DoHandShake(void* const connectionPtr, std::unique_ptr<Sgx::RaProcessorClient>& raProcessor)
{
	if (!connectionPtr || !raProcessor)
	{
		return nullptr;
	}

	int retVal = 0;
	if (ocall_sgx_ra_send_msg0s(&retVal, connectionPtr) != SGX_SUCCESS ||
		!retVal)
	{
		return nullptr;
	}

	std::string buf1;
	std::string buf2;

	sgx_ra_msg1_t msg1;
	std::vector<uint8_t> msg3;

	if (!StaticConnection::ReceivePack(connectionPtr, buf1) ||
		buf1.size() != sizeof(sgx_ra_msg0r_t) ||
		!raProcessor->ProcessMsg0r(*reinterpret_cast<const sgx_ra_msg0r_t*>(buf1.data()), msg1) ||
		!StaticConnection::SendAndReceivePack(connectionPtr, &msg1, sizeof(msg1), buf1) ||
		buf1.size() < sizeof(sgx_ra_msg2_t) || 
		!raProcessor->ProcessMsg2(*reinterpret_cast<const sgx_ra_msg2_t*>(buf1.data()), buf1.size(), msg3) ||
		!StaticConnection::SendAndReceivePack(connectionPtr, msg3.data(), msg3.size(), buf1) || 
		buf1.size() != sizeof(sgx_ra_msg4_t) ||
		!raProcessor->ProcessMsg4(*reinterpret_cast<const sgx_ra_msg4_t*>(buf1.data())) )
	{
		return nullptr;
	}

	return std::move(raProcessor);
}

RaClientCommLayer::RaClientCommLayer(void* const connectionPtr, std::unique_ptr<Sgx::RaProcessorClient>& raProcessor) :
	RaClientCommLayer(DoHandShake(connectionPtr, raProcessor))
{
}

RaClientCommLayer::RaClientCommLayer(RaClientCommLayer && other) :
	AESGCMCommLayer(std::forward<AESGCMCommLayer>(other)),
	m_isHandShaked(other.m_isHandShaked),
	m_iasReport(std::move(other.m_iasReport))
{
	other.m_isHandShaked = false;
}

const sgx_ias_report_t & RaClientCommLayer::GetIasReport() const
{
	return *m_iasReport;
}

RaClientCommLayer::~RaClientCommLayer()
{
}

RaClientCommLayer::operator bool() const
{
	return AESGCMCommLayer::operator bool() && m_isHandShaked;
}

RaClientCommLayer::RaClientCommLayer(std::unique_ptr<Sgx::RaProcessorClient> raProcessor) :
	AESGCMCommLayer(raProcessor && raProcessor->IsAttested() ? raProcessor->GetSK() : General128BitKey()),
	m_isHandShaked(raProcessor && raProcessor->IsAttested()),
	m_iasReport(m_isHandShaked ? raProcessor->ReleaseIasReport() : new sgx_ias_report_t)
{
}
