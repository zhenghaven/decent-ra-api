#include "DecentralizedEnclave.h"

DecentralizedEnclave::DecentralizedEnclave(std::shared_ptr<EnclaveBase> enclaveHardware) :
	m_enclaveHardware(enclaveHardware)
{
}

DecentralizedEnclave::~DecentralizedEnclave()
{
}

std::shared_ptr<EnclaveBase> DecentralizedEnclave::GetEnclaveHardware()
{
	return m_enclaveHardware;
}

const std::shared_ptr<const EnclaveBase>& DecentralizedEnclave::GetEnclaveHardware() const
{
	return m_enclaveHardware;
}
