#include "../../common/ModuleConfigInternal.h"
#if USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL

#pragma once

#include <string>
#include <memory>

class SecureCommLayer;

namespace DecentEnclave
{
	void DropDecentNode(const std::string& nodeID);
	//std::shared_ptr<const SecureCommLayer> ReleaseCommLayer(const std::string& nodeID);
	bool IsAttested(const std::string& nodeID);
}

#endif //USE_INTEL_SGX_ENCLAVE_INTERNAL && USE_DECENT_ENCLAVE_SERVER_INTERNAL
