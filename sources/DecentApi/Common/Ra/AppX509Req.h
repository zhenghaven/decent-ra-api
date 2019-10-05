#pragma once

#include "../MbedTls/X509Req.h"

namespace Decent
{
	namespace MbedTlsObj
	{
		class RbgBase;
		class EcKeyPairBase;
	}

	namespace Ra
	{
		class AppX509ReqWriter : public MbedTlsObj::X509ReqWriter
		{
		public:
			AppX509ReqWriter() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param 		  	hashType  	Type of the hash.
			 * \param [in,out]	keyPair   	The key pair.
			 * \param 		  	commonName	Common Name.
			 */
			AppX509ReqWriter(MbedTlsObj::HashType hashType, MbedTlsObj::EcKeyPairBase & keyPair, const std::string& commonName);

			virtual ~AppX509ReqWriter();
		};

		class AppX509Req : public MbedTlsObj::X509Req
		{
		public:
			AppX509Req() = delete;

			AppX509Req(const AppX509Req& rhs) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			AppX509Req(AppX509Req&& rhs);

			/**
			 * \brief	Constructs X509 Certificate Request from DER encoded bytes.
			 *
			 * \param	pem	The DER encoded bytes.
			 */
			AppX509Req(const std::vector<uint8_t>& der);

			/**
			 * \brief	Constructs X509 Certificate Request from PEM encoded string.
			 *
			 * \param	pem	The PEM encoded string.
			 */
			AppX509Req(const std::string& pem);

			/**
			 * \brief	Constructs X509 Certificate Request directly from X509 CSR writer object. A DER
			 * 			encoded bytes will be generated and given to this instance.
			 *
			 * \param [in,out]	writer	The X509 CSR writer.
			 * \param [in,out]	rbg   	The Random Bit Generator.
			 */
			AppX509Req(AppX509ReqWriter& writer, MbedTlsObj::RbgBase& rbg);

			/** \brief	Destructor */
			virtual ~AppX509Req();

			virtual AppX509Req& operator=(const AppX509Req& rhs) = delete;

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			virtual AppX509Req& operator=(AppX509Req&& rhs);
		};
	}
}
