//#if ENCLAVE_PLATFORM_SGX

#include "../UntrustedBuffer.h"

#include "../../SGX/edl_decent_tools.h"

using namespace Decent::Tools;

UntrustedBuffer::~UntrustedBuffer()
{
	ocall_decent_tools_del_buf_uint8(m_ptr);
}

//#endif //ENCLAVE_PLATFORM_SGX
