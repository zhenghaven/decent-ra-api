#include "../common/CryptoKeyContainer.h"

#include "../common/MbedTlsObjects.h"

CryptoKeyContainer::CryptoKeyContainer() :
	CryptoKeyContainer(new MbedTlsObj::ECKeyPair(MbedTlsObj::gen))
{
}
