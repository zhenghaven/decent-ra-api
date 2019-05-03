#include "RaClientCommLayer.h"

#include "../Net/EnclaveCntTranslator.h"
#include "../../Common/Net/NetworkException.h"
#include "../../Common/SGX/sgx_structs.h"

#include "RaProcessorClient.h"
#include "edl_decent_sgx_client.h"

using namespace Decent::Sgx;
using namespace Decent::Net;

static std::unique_ptr<RaProcessorClient> DoHandShake(EnclaveCntTranslator& connection, std::unique_ptr<RaProcessorClient>& raProcessor)
{
	if (!raProcessor)
	{
		throw Exception("Null pointer is given to the Decent::Sgx::RaProcessorClient DoHandShake.");
	}

	int retVal = 0;
	if (ocall_decent_sgx_ra_send_msg0s(&retVal, connection.GetPointer()) != SGX_SUCCESS ||
		!retVal)
	{
		throw Exception("Decent::Sgx::RaProcessorClient DoHandShake Failed.");
	}

	std::string buf1;
	std::string buf2;

	sgx_ra_msg1_t msg1;
	std::vector<uint8_t> msg3;

	connection.ReceivePack(buf1);
	if (buf1.size() != sizeof(sgx_ra_msg0r_t) ||
		!raProcessor->ProcessMsg0r(*reinterpret_cast<const sgx_ra_msg0r_t*>(buf1.data()), msg1))
	{
		throw Exception("Decent::Sgx::RaProcessorClient DoHandShake Failed.");
	}

	connection.SendAndReceivePack(&msg1, sizeof(msg1), buf1);
	if (buf1.size() < sizeof(sgx_ra_msg2_t) ||
		!raProcessor->ProcessMsg2(*reinterpret_cast<const sgx_ra_msg2_t*>(buf1.data()), buf1.size(), msg3))
	{
		throw Exception("Decent::Sgx::RaProcessorClient DoHandShake Failed.");
	}

	connection.SendAndReceivePack(msg3.data(), msg3.size(), buf1);
	if (buf1.size() != sizeof(sgx_ra_msg4_t) ||
		!raProcessor->ProcessMsg4(*reinterpret_cast<const sgx_ra_msg4_t*>(buf1.data())))
	{
		throw Exception("Decent::Sgx::RaProcessorClient DoHandShake Failed.");
	}

	return std::move(raProcessor);
}

RaClientCommLayer::RaClientCommLayer(EnclaveCntTranslator& connection, std::unique_ptr<RaProcessorClient>& raProcessor) :
	RaClientCommLayer(DoHandShake(connection, raProcessor))
{
}

RaClientCommLayer::RaClientCommLayer(RaClientCommLayer && other) :
	AesGcmCommLayer(std::forward<AesGcmCommLayer>(other)),
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
	return AesGcmCommLayer::operator bool() && m_isHandShaked;
}

RaClientCommLayer::RaClientCommLayer(std::unique_ptr<RaProcessorClient> raProcessor) :
	AesGcmCommLayer(raProcessor && raProcessor->IsAttested() ? raProcessor->GetSK() : General128BitKey()),
	m_isHandShaked(raProcessor && raProcessor->IsAttested()),
	m_iasReport(m_isHandShaked ? raProcessor->ReleaseIasReport() : new sgx_ias_report_t)
{
}
