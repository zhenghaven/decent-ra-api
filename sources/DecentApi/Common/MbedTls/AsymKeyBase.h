#pragma once

#include "ObjBase.h"

#include <vector>
#include <string>

typedef struct mbedtls_pk_context mbedtls_pk_context;
typedef struct mbedtls_ecp_keypair mbedtls_ecp_keypair;
typedef struct mbedtls_rsa_context mbedtls_rsa_context;

namespace Decent
{
	namespace MbedTlsObj
	{
		class RbgBase;

		class AsymKeyBase : public ObjBase<mbedtls_pk_context>
		{
		public: //static member:

			/**
			 * \brief	Function that frees MbedTLS object and delete the pointer.
			 *
			 * \param [in,out]	ptr	If non-null, the pointer.
			 */
			static void FreeObject(mbedtls_pk_context* ptr);

			/**
			 * \brief	Gets key algorithm type from context
			 *
			 * \param [in,out]	ctx	The context.
			 *
			 * \return	The algorithm type from context.
			 */
			static AsymAlgmType GetAlgmTypeFromContext(const mbedtls_pk_context& ctx);

			/**
			 * \brief	Gets key type (either public or private) from context.
			 *
			 * \param [in,out]	ctx	The context.
			 *
			 * \return	The key type from context.
			 */
			static AsymKeyType GetKeyTypeFromContext(mbedtls_pk_context& ctx, RbgBase& rbg);
			static AsymKeyType GetKeyTypeFromContext(mbedtls_ecp_keypair& ctx, RbgBase& rbg);
			static AsymKeyType GetKeyTypeFromContext(mbedtls_rsa_context& ctx);
			static AsymKeyType GetKeyTypeFromContext(const mbedtls_pk_context& ctx);
			static AsymKeyType GetKeyTypeFromContext(const mbedtls_ecp_keypair& ctx);
			static AsymKeyType GetKeyTypeFromContext(const mbedtls_rsa_context& ctx);

			/**
			 * \brief	Check public key in context is valid or not
			 *
			 * \param	ctx	The context.
			 *
			 * \return	True if it succeeds, false if it fails.
			 */
			static bool CheckPublicKeyInContext(const mbedtls_ecp_keypair& ctx);
			static bool CheckPublicKeyInContext(const mbedtls_rsa_context& ctx);

			/**
			 * \brief	Check private key in context is valid or not
			 *
			 * \param	ctx	The context.
			 *
			 * \return	True if it succeeds, false if it fails.
			 */
			static bool CheckPrivateKeyInContext(const mbedtls_ecp_keypair& ctx);
			static bool CheckPrivateKeyInContext(const mbedtls_rsa_context& ctx);

			/**
			 * \brief	Complete public key in context based on the existing private key.
			 *
			 * \param [in,out]	ctx	The context.
			 */
			static void CompletePublicKeyInContext(mbedtls_ecp_keypair& ctx, RbgBase& rbg);
			static void CompletePublicKeyInContext(mbedtls_rsa_context& ctx);

		public:

			/** \brief	Default constructor. Constructs a non-null, initialized, but empty Public Key context. */
			AsymKeyBase();

			AsymKeyBase(const AsymKeyBase& rhs) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			AsymKeyBase(AsymKeyBase&& rhs);

			/**
			 * \brief	Constructs public key by reading PEM from a string.
			 *
			 * \param	pem	The PEM.
			 */
			AsymKeyBase(const std::string& pem);

			/**
			 * \brief	Constructs public key by reading DER from a byte array.
			 *
			 * \param	der	The DER.
			 */
			AsymKeyBase(const std::vector<uint8_t>& der);

			/** \brief	Destructor */
			virtual ~AsymKeyBase();

			AsymKeyBase& operator=(const AsymKeyBase& rhs) = delete;

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			AsymKeyBase& operator=(AsymKeyBase&& rhs);

			/**
			 * \brief	Query if this object is null. It is considered as null if the pointer is null (refer
			 * 			to ObjBase), or the key type is MBEDTLS_PK_NONE
			 *
			 * \return	True if null, false if not.
			 */
			virtual bool IsNull() const override;

			using ObjBase::Swap;

			/**
			 * \brief	Gets asymmetric key algorithm type.
			 *
			 * \return	The asymmetric key algorithm type.
			 */
			virtual AsymAlgmType GetAlgmType() const;

			/**
			 * \brief	Gets asymmetric key type (either public or private).
			 *
			 * \return	The asymmetric key type.
			 */
			virtual AsymKeyType GetKeyType() const;

			/**
			 * \brief	Verify DER encoded signature
			 *
			 * \tparam	containerType1	Type of the container for hash.
			 * \tparam	containerType2	Type of the container for signature.
			 * \param	hashType	Type of the hash.
			 * \param	hash		The hash.
			 * \param	sign		The signature.
			 */
			template<typename containerType1, typename containerType2>
			void VerifyDerSign(HashType hashType, const containerType1& hash, const containerType2& sign) const
			{
				return VrfyDerSignNoBufferCheck(hashType, detail::GetPtr(hash), detail::GetSize(hash),
					detail::GetPtr(sign), detail::GetSize(sign));
			}

		protected:

			AsymKeyBase(mbedtls_pk_context* ptr, FreeFuncType freeFunc);

			virtual void VrfyDerSignNoBufferCheck(HashType hashType, const void* hashBuf, size_t hashSize, const void* signBuf, size_t signSize) const;

			virtual std::vector<uint8_t> GetPublicDer(size_t maxBufSize) const;

			virtual std::string GetPublicPem(size_t maxBufSize) const;

			virtual void GetPrivateDer(std::vector<uint8_t>& out, size_t maxBufSize) const;

			virtual void GetPrivatePem(std::string& out, size_t maxBufSize) const;
		};
	}
}
