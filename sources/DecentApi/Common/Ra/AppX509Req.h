#pragma once

#include <mbedTLScpp/X509Req.hpp>
#include <mbedTLScpp/EcKey.hpp>

namespace Decent
{
	namespace Ra
	{
		class AppX509ReqWriter : public mbedTLScpp::X509ReqWriter
		{
		public: // Static members:

			using _Base = mbedTLScpp::X509ReqWriter;

		public:
			AppX509ReqWriter() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param 		  	hashType  	Type of the hash.
			 * \param [in,out]	keyPair   	The key pair.
			 * \param 		  	commonName	Common Name.
			 */
			template<typename _PKObjTrait>
			AppX509ReqWriter(mbedTLScpp::HashType hashType,
				const mbedTLScpp::EcKeyPairBase<_PKObjTrait>& keyPair,
				const std::string& commonName) :
				_Base::X509ReqWriter(hashType, keyPair, ("CN=" + commonName))
			{}

			virtual ~AppX509ReqWriter()
			{}
		};
	}
}
