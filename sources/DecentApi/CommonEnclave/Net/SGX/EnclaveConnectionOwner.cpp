//#if ENCLAVE_PLATFORM_SGX

#include "../../SGX/edl_decent_net.h"
#include "../EnclaveConnectionOwner.h"

using namespace Decent::Net;

EnclaveConnectionOwner::~EnclaveConnectionOwner()
{
	ocall_decent_net_cnet_close(m_cntPtr);
	m_cntPtr = nullptr;
}

//#endif //ENCLAVE_PLATFORM_SGX
