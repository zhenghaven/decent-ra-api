#pragma once

#include "EnclaveBase.h"
#include "ServiceProviderBase.h"

class EnclaveServiceProviderBase : virtual public EnclaveBase, virtual public ServiceProviderBase
{
};
