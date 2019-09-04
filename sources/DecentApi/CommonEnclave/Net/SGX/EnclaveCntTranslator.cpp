//#if ENCLAVE_PLATFORM_SGX

#include "../../../Common/Net/NetworkException.h"

#include "../../SGX/edl_decent_net.h"
#include "../../SGX/edl_decent_tools.h"

#include "../../Tools/UntrustedBuffer.h"

#include "../EnclaveCntTranslator.h"

using namespace Decent::Net;
using namespace Decent::Tools;

#define CHECK_SGX_ERROR(X) if (X != SGX_SUCCESS) { throw Decent::Net::Exception("OCall to send message pack failed with SGX error code: " + std::to_string(X)); }
#define CHECK_OCALL_BOOL_RET(X) if (!X) { throw Decent::Net::Exception("OCall to send message pack returned false."); }

size_t EnclaveCntTranslator::SendRaw(const void * const dataPtr, const size_t size)
{
	int sentRes = 0;
	size_t sentSize = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_raw(&sentRes, &sentSize, m_cntPtr, static_cast<const uint8_t*>(dataPtr), size);

	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(sentRes);
	return sentSize;
}

size_t EnclaveCntTranslator::RecvRaw(void * const bufPtr, const size_t size)
{
	int recvRes = 0;
	size_t recvSize = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_raw(&recvRes, &recvSize, m_cntPtr, static_cast<uint8_t*>(bufPtr), size);

	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(recvRes);
	return recvSize;
}

void EnclaveCntTranslator::SendPack(const void * const dataPtr, const size_t size)
{
	int sentRes = 0;
	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_pack(&sentRes, m_cntPtr, static_cast<const uint8_t*>(dataPtr), size);

	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(sentRes);
}

size_t EnclaveCntTranslator::RecvPack(uint8_t*& dest)
{
	int sentRes = 0;
	size_t size = 0;
	uint8_t* bufPtr = nullptr;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_recv_pack(&sentRes, m_cntPtr, &bufPtr, &size);
	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(sentRes);

	dest = new uint8_t[size];

	UntrustedBuffer(bufPtr, size).Read(dest, size);

	return size;
}

std::vector<uint8_t> EnclaveCntTranslator::SendAndRecvPack(const void * const inData, const size_t inDataLen)
{
	int retVal = 0;
	size_t size = 0;
	uint8_t* bufPtr = nullptr;

	sgx_status_t enclaveRet = ocall_decent_net_cnet_send_and_recv_pack(&retVal, m_cntPtr, static_cast<const uint8_t*>(inData), inDataLen, &bufPtr, &size);
	CHECK_SGX_ERROR(enclaveRet);
	CHECK_OCALL_BOOL_RET(retVal);

	return UntrustedBuffer(bufPtr, size).Read();
}

void EnclaveCntTranslator::Terminate() noexcept
{
	ocall_decent_net_cnet_terminate(m_cntPtr);
}

//#endif //ENCLAVE_PLATFORM_SGX
