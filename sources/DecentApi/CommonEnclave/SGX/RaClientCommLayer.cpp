#include "RaClientCommLayer.h"

#include "../Net/EnclaveCntTranslator.h"
#include "../../Common/Net/NetworkException.h"
#include "../../Common/SGX/sgx_structs.h"

#include "RaProcessorClient.h"
#include "edl_decent_sgx_client.h"

using namespace Decent::Sgx;
using namespace Decent::Net;

static std::pair<std::unique_ptr<RaProcessorClient>, ConnectionBase*> DoHandShake(ConnectionBase& connection, std::unique_ptr<RaProcessorClient>& raProcessor)
{
	if (!raProcessor)
	{
		throw Exception("Null pointer is given to the Decent::Sgx::RaProcessorClient DoHandShake.");
	}

	sgx_ra_msg0s_t msg0s;
	sgx_ra_msg0r_t msg0r;
	sgx_ra_msg1_t msg1;
	std::vector<uint8_t> msg2;
	std::vector<uint8_t> msg3;
	sgx_ra_msg4_t msg4;

	raProcessor->GetMsg0s(msg0s);

	connection.SendRawGuarantee(&msg0s, sizeof(msg0s));
	connection.ReceiveRawGuarantee(&msg0r, sizeof(msg0r));

	raProcessor->ProcessMsg0r(msg0r, msg1);

	connection.SendRawGuarantee(&msg1, sizeof(msg1));
	connection.ReceivePack(msg2);

	if (msg2.size() < sizeof(sgx_ra_msg2_t))
	{
		throw Exception("Decent::Sgx::RaProcessorClient DoHandShake Failed.");
	}

	raProcessor->ProcessMsg2(*reinterpret_cast<const sgx_ra_msg2_t*>(msg2.data()), msg2.size(), msg3);

	connection.SendPack(msg3);
	connection.ReceiveRawGuarantee(&msg4, sizeof(msg4));

	raProcessor->ProcessMsg4(msg4);

	return std::make_pair(std::move(raProcessor), &connection);
}

RaClientCommLayer::RaClientCommLayer(ConnectionBase& connection, std::unique_ptr<RaProcessorClient>& raProcessor) :
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

RaClientCommLayer::RaClientCommLayer(std::pair<std::unique_ptr<RaProcessorClient>, ConnectionBase*> raProcessor) :
	AesGcmCommLayer(raProcessor.first && raProcessor.first->IsAttested() ? raProcessor.first->GetSK() : General128BitKey(), raProcessor.second),
	m_isHandShaked(raProcessor.first && raProcessor.first->IsAttested()),
	m_iasReport(m_isHandShaked ? raProcessor.first->ReleaseIasReport() : new sgx_ias_report_t)
{
}
