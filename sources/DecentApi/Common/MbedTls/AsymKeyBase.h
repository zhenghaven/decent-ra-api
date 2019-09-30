#pragma once

#include "ObjBase.h"

#include <vector>
#include <string>

typedef struct mbedtls_pk_context mbedtls_pk_context;

namespace Decent
{
	namespace MbedTlsObj
	{
		class AsymKeyBase : public ObjBase<mbedtls_pk_context>
		{
		public: //static member:

			/**
			 * \brief	Function that frees MbedTLS object and delete the pointer.
			 *
			 * \param [in,out]	ptr	If non-null, the pointer.
			 */
			static void FreeObject(mbedtls_pk_context* ptr);

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
			virtual AsymAlgmType GetAlgmType() const = 0;

			/**
			 * \brief	Gets asymmetric key type (either public or private).
			 *
			 * \return	The asymmetric key type.
			 */
			virtual AsymKeyType GetKeyType() const = 0;

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
		};
	}
}
