#include "AppX509Req.h"

#include "../MbedTls/RbgBase.h"
#include "../MbedTls/EcKey.h"

using namespace Decent::Ra;
using namespace Decent::MbedTlsObj;

AppX509ReqWriter::AppX509ReqWriter(HashType hashType, EcKeyPairBase & keyPair, const std::string & commonName) :
	X509ReqWriter(hashType, keyPair, commonName)
{
}

AppX509ReqWriter::~AppX509ReqWriter()
{
}

AppX509Req::AppX509Req(AppX509Req && rhs) :
	MbedTlsObj::X509Req(std::forward<MbedTlsObj::X509Req>(rhs))
{
}

AppX509Req::AppX509Req(const std::vector<uint8_t>& der) :
	MbedTlsObj::X509Req(der)
{
}

AppX509Req::AppX509Req(const std::string & pem) :
	MbedTlsObj::X509Req(pem)
{
}

AppX509Req::AppX509Req(AppX509ReqWriter & writer, RbgBase & rbg) :
	MbedTlsObj::X509Req(writer.GenerateDer(rbg))
{
}

AppX509Req::~AppX509Req()
{
}

AppX509Req & AppX509Req::operator=(AppX509Req && rhs)
{
	MbedTlsObj::X509Req::operator=(std::forward<MbedTlsObj::X509Req>(rhs));
	return *this;
}
