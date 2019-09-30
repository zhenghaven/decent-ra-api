#pragma once

#include "AsymKeyBase.h"

#include <memory>

typedef struct mbedtls_ecp_keypair mbedtls_ecp_keypair;

namespace Decent
{
	namespace MbedTlsObj
	{
		class BigNumberBase;

		/**
		 * \brief	Gets Elliptic Curve size in Byte
		 *
		 * \exception	MbedTlsObj::RuntimeException	Thrown when Invalid Elliptic Curve type is given.
		 *
		 * \param	type	The curve type.
		 *
		 * \return	The size in Byte.
		 */
		inline constexpr size_t GetCurveByteSize(EcKeyType type)
		{
			switch (type)
			{
			case Decent::MbedTlsObj::EcKeyType::SECP192R1:
			case Decent::MbedTlsObj::EcKeyType::SECP192K1:
				return 24U;
			case Decent::MbedTlsObj::EcKeyType::SECP224R1:
			case Decent::MbedTlsObj::EcKeyType::SECP224K1:
				return 28U;
			case Decent::MbedTlsObj::EcKeyType::SECP256R1:
			case Decent::MbedTlsObj::EcKeyType::SECP256K1:
			case Decent::MbedTlsObj::EcKeyType::BP256R1:
				return 32U;
			case Decent::MbedTlsObj::EcKeyType::SECP384R1:
			case Decent::MbedTlsObj::EcKeyType::BP384R1:
				return 48U;
			case Decent::MbedTlsObj::EcKeyType::BP512R1:
				return 64U;
			case Decent::MbedTlsObj::EcKeyType::SECP521R1:
				return 66U;
			default:
				throw MbedTlsObj::RuntimeException("Invalid Elliptic Curve type is given!");
			}
		}

		/**
		 * \brief	Gets Elliptic Curve size in Byte at compile time.
		 *
		 * \tparam	type	The curve type.
		 *
		 * \return	The size in Byte.
		 */
		template<EcKeyType type>
		inline constexpr size_t GetCurveByteSize()
		{
			return GetCurveByteSize(type);
		}

		class EcPublicKeyBase : public AsymKeyBase
		{
		public:
			EcPublicKeyBase() = delete;

			EcPublicKeyBase(const EcPublicKeyBase& rhs) = delete;

			EcPublicKeyBase(EcPublicKeyBase&& rhs);

			/**
			 * \brief	Constructor that obtain the ownership of a existing mbedTLS PK context object.
			 *
			 * \param	other	The other.
			 */
			EcPublicKeyBase(std::unique_ptr<mbedtls_pk_context> other);

			/**
			 * \brief	Constructs public key by referring to a existing mbedTLS PK context object. NOTE:
			 * 			this instance DOES NOT has the ownership! That means, the existing mbedTLS PK context
			 * 			object must have longer life time than this instance!
			 *
			 * \param [in,out]	other	The other.
			 */
			EcPublicKeyBase(mbedtls_pk_context& other);

			/**
			 * \brief	Constructs public key by reading PEM from a string.
			 *
			 * \param	pem	The PEM.
			 */
			EcPublicKeyBase(const std::string& pem);

			/**
			 * \brief	Constructs public key by reading DER from a byte array.
			 *
			 * \param	der	The DER.
			 */
			EcPublicKeyBase(const std::vector<uint8_t>& der);

			/**
			 * \brief	Constructor from public key's X and Y values (Z is 1).
			 *
			 * \param	ecType	The type of Elliptic Curve.
			 * \param	x	  	Elliptic Curve public key's X value.
			 * \param	y	  	Elliptic Curve public key's Y value.
			 */
			EcPublicKeyBase(EcKeyType ecType, const BigNumberBase& x, const BigNumberBase& y);

			/** \brief	Destructor */
			virtual ~EcPublicKeyBase();

		protected: //protected (de-)con-structors:

			EcPublicKeyBase(EcKeyType ecType);

		public:

			EcPublicKeyBase& operator=(const EcPublicKeyBase& rhs) = delete;

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A shallow copy of this object.
			 */
			EcPublicKeyBase& operator=(EcPublicKeyBase&& rhs);

			/**
			 * \brief	Gets asymmetric key algorithm type.
			 *
			 * \return	The asymmetric key algorithm type.
			 */
			virtual AsymAlgmType GetAlgmType() const override;

			/**
			 * \brief	Gets asymmetric key type (either public or private).
			 *
			 * \return	The asymmetric key type.
			 */
			virtual AsymKeyType GetKeyType() const override;

			/**
			 * \brief	Gets Elliptic Curve type
			 *
			 * \return	The Elliptic Curve type.
			 */
			virtual EcKeyType GetCurveType() const;

			/**
			 * \brief	Gets mbedTLS's EC key pair context.
			 *
			 * \return	The mbedTLS's EC key pair context.
			 */
			mbedtls_ecp_keypair& GetEcContext();

			/**
			 * \brief	Gets mbedTLS's EC key pair context.
			 *
			 * \return	The mbedTLS's EC key pair context.
			 */
			const mbedtls_ecp_keypair& GetEcContext() const;

			/**
			 * \brief	Gets public key encoded in DER
			 *
			 * \return	The DER encoded public key stored in byte array.
			 */
			virtual std::vector<uint8_t> GetPublicDer() const;

			/**
			 * \brief	Gets public key encoded in PEM
			 *
			 * \return	The PEM encoded public key stored in string.
			 */
			virtual std::string GetPublicPem() const;

			/**
			 * \brief	Verify signature.
			 *
			 * \tparam	containerType	Type of the container for the hash.
			 * \param	hash	The hash.
			 * \param	r   	Elliptic Curve signature's R value.
			 * \param	s   	Elliptic Curve signature's S value.
			 */
			template<typename containerType>
			void VerifySign(const containerType& hash, const BigNumberBase& r, const BigNumberBase& s) const
			{
				return VerifySign(detail::GetPtr(hash), detail::GetSize(hash), r, s);
			}

			/**
			 * \brief	Exports this public key to binary format.
			 *
			 * \tparam	containerXType	Type of the container for X.
			 * \tparam	containerYType	Type of the container for Y.
			 * \param [out]	x	Elliptic Curve public key's X value.
			 * \param [out]	y	Elliptic Curve public key's Y value.
			 */
			template<typename containerXType, typename containerYType>
			void ToPublicBinary(containerXType& x, containerYType& y) const
			{
				return ToPublicBinary(detail::GetPtr(x), detail::GetSize(x), detail::GetPtr(y), detail::GetSize(y));
			}

		protected:

			void VerifySign(const void* hashBuf, size_t hashSize, const BigNumberBase& r, const BigNumberBase& s) const;

			void ToPublicBinary(void* xPtr, size_t xSize, void* yPtr, size_t ySize) const;
		};

		class EcKeyPairBase : public EcPublicKeyBase
		{
		public:
			EcKeyPairBase() = delete;

			EcKeyPairBase(const Generate&);

			EcKeyPairBase(const EcKeyPairBase& rhs) = delete;

			EcKeyPairBase(EcKeyPairBase&& rhs);

			/**
			 * \brief	Constructor that obtain the ownership of a existing mbedTLS PK context object.
			 *
			 * \param	other	The other.
			 */
			EcKeyPairBase(std::unique_ptr<mbedtls_pk_context> other);

			/**
			 * \brief	Constructs public key by referring to a existing mbedTLS PK context object. NOTE:
			 * 			this instance DOES NOT has the ownership! That means, the existing mbedTLS PK context
			 * 			object must have longer life time than this instance!
			 *
			 * \param [in,out]	other	The other.
			 */
			EcKeyPairBase(mbedtls_pk_context& other);

			/**
			 * \brief	Constructs public key by reading PEM from a string.
			 *
			 * \param	pem	The PEM.
			 */
			EcKeyPairBase(const std::string& pem);

			/**
			 * \brief	Constructs public key by reading DER from a byte array.
			 *
			 * \param	der	The DER.
			 */
			EcKeyPairBase(const std::vector<uint8_t>& der);

			/**
			 * \brief	Constructor from public key's X and Y values (Z is 1).
			 *
			 * \param	ecType	The type of Elliptic Curve.
			 * \param	r	  	Elliptic Curve private key's R value.
			 */
			EcKeyPairBase(EcKeyType ecType, const BigNumberBase& r);

			/**
			 * \brief	Constructor from public key's X and Y values (Z is 1).
			 *
			 * \param	ecType	The type of Elliptic Curve.
			 * \param	r	  	Elliptic Curve private key's R value.
			 * \param	x	  	Elliptic Curve public key's X value.
			 * \param	y	  	Elliptic Curve public key's Y value.
			 */
			EcKeyPairBase(EcKeyType ecType, const BigNumberBase& r, const BigNumberBase& x, const BigNumberBase& y);

			virtual ~EcKeyPairBase();

		public:

			EcKeyPairBase& operator=(const EcKeyPairBase& rhs) = delete;

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A shallow copy of this object.
			 */
			EcKeyPairBase& operator=(EcKeyPairBase&& rhs);

			/**
			 * \brief	Gets asymmetric key type (either public or private).
			 *
			 * \return	The asymmetric key type.
			 */
			virtual AsymKeyType GetKeyType() const override;

			/**
			 * \brief	Gets private key encoded in DER
			 *
			 * \return	The DER encoded private key stored in byte array.
			 */
			virtual std::vector<uint8_t> GetPrivateDer() const;

			/**
			 * \brief	Gets private key encoded in PEM
			 *
			 * \return	The PEM encoded private key stored in string.
			 */
			virtual std::string GetPrivatePem() const;

			/**
			 * \brief	Verify signature.
			 *
			 * \tparam	containerHType	Type of the container for the hash.
			 * \tparam	containerRType	Type of the container for the R.
			 * \tparam	containerSType	Type of the container for the S.
			 * \param 	   	hashType	Type of the hash.
			 * \param 	   	hash		The hash.
			 * \param [out]	r			Elliptic Curve signature's R value.
			 * \param [out]	s			Elliptic Curve signature's S value.
			 */
			template<typename containerHType, typename containerRType, typename containerSType>
			void Sign(HashType hashType, const containerHType& hash, containerRType& r, containerSType& s) const
			{
				return Sign(hashType, detail::GetPtr(hash), detail::GetSize(hash),
					detail::GetPtr(r), detail::GetSize(r), detail::GetPtr(s), detail::GetSize(s));
			}

			/**
			 * \brief	Exports this public key to binary format.
			 *
			 * \tparam	containerXType	Type of the container for X.
			 * \tparam	containerYType	Type of the container for Y.
			 * \param [out]	x	Elliptic Curve public key's X value.
			 * \param [out]	y	Elliptic Curve public key's Y value.
			 */
			template<typename containerRType>
			void ToPrivateBinary(containerRType& r) const
			{
				return ToPrivateBinary(detail::GetPtr(r), detail::GetSize(r));
			}

			/**
			 * \brief	Derive shared key
			 *
			 * \tparam	containerType	Type of the container.
			 * \param [out]	key   	The derived key.
			 * \param 	   	pubKey	The public key.
			 */
			template<typename containerType>
			void DeriveSharedKey(containerType& key, const EcPublicKeyBase& pubKey) const
			{
				return DeriveSharedKey(detail::GetPtr(key), detail::GetSize(key), pubKey);
			}

		protected:

			void Sign(HashType hashType, const void* hashBuf, size_t hashSize, void* rPtr, size_t rSize, void* sPtr, size_t sSize) const;

			void ToPrivateBinary(void* rPtr, size_t rSize) const;

			void DeriveSharedKey(void* bufPtr, size_t bufSize, const EcPublicKeyBase& pubKey) const;

		};
	}
}
