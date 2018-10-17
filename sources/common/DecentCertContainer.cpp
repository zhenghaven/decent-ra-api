#include "DecentCertContainer.h"

DecentCertContainer & DecentCertContainer::Get()
{
	static DecentCertContainer inst;
	return inst;
}
