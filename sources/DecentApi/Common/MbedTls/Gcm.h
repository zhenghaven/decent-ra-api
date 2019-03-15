#pragma once

#include "ObjBase.h"

#include <array>

typedef struct mbedtls_gcm_context mbedtls_gcm_context;

namespace Decent
{
	namespace MbedTlsObj
	{

		/** \brief	A GCM base class. General GCM functionalities are defined here.   */
		class GcmBase : public ObjBase<mbedtls_gcm_context>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_gcm_context* ptr);

			/** \brief	Values that represent cipher types */
			enum class Cipher
			{
				AES,
			};

		public:

			/**
			 * \brief	Construct an empty but valid GCM object.
			 *
			 * \param	parameter1	Indicate the need to generate an empty GCM object.
			 */
			GcmBase(const Empty&);

			/**
			* \brief	Constructor that accept a reference to mbedtls_gcm_context object, thus, this instance doesn't
			* 			has the ownership.
			*
			* \param [in,out]	ref	The reference.
			*/
			GcmBase(mbedtls_gcm_context& ref) noexcept :
				ObjBase(&ref, &ObjBase::DoNotFree)
			{}

			/**
			* \brief	Move constructor
			*
			* \param [in,out]	other	The other.
			*/
			GcmBase(GcmBase&& other) noexcept :
				ObjBase(std::forward<ObjBase>(other))
			{}

			/** \brief	Destructor */
			virtual ~GcmBase() {}

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	other	The other.
			 *
			 * \return	A reference to this object.
			 */
			virtual GcmBase& operator=(GcmBase&& other) noexcept
			{
				ObjBase::operator=(std::forward<ObjBase>(other));
				return *this;
			}

			/**
			 * \brief	Encrypts a structure
			 *
			 * \exception MbedTlsObj::RuntimeException
			 *
			 * \tparam	AddCtar	Data Type of the additional authentication.
			 * \tparam	IvStru 	Data Type of the IV.
			 * \tparam	TagStru	Data Type of the Tag.
			 * 					
			 * \param 		  	inData 	Input data to be encrypted.
			 * \param 		  	inLen  	Size of the input data.
			 * \param [in,out]	outData	Output encrypted data.
			 * \param 		  	outLen 	Size of the output buffer.
			 * \param 		  	iv	   	The iv.
			 * \param 		  	add	   	The additional authentication info.
			 * \param [in,out]	outTag 	The out tag.
			 */
			template<typename AddCtar, typename IvStru, typename TagStru>
			void Encrypt(const void* inData, const size_t inLen, void* outData, const size_t outLen,
				const IvStru& iv, const AddCtar& add, TagStru& outTag)
			{
				Encrypt(inData, inLen, outData, outLen,
					detail::GetPtr(iv), detail::GetSize(iv), detail::GetPtr(add), detail::GetSize(add),
					detail::GetPtr(outTag), detail::GetSize(outTag));
			}

			/**
			 * \brief	Encrypts a structure
			 *
			 * \exception MbedTlsObj::RuntimeException
			 *
			 * \tparam	IvStru 	Data Type of the IV.
			 * \tparam	TagStru	Data Type of the Tag.
			 * 					
			 * \param 		  	inData 	Input data to be encrypted.
			 * \param 		  	inLen  	Size of the input data.
			 * \param [in,out]	outData	Output encrypted data.
			 * \param 		  	outLen 	Size of the output buffer.
			 * \param 		  	iv	   	The iv.
			 * \param [in,out]	outTag 	The out tag.
			 */
			template<typename IvStru, typename TagStru>
			void Encrypt(const void* inData, const size_t inLen, void* outData, const size_t outLen,
				const IvStru& iv, TagStru& outTag)
			{
				Encrypt(inData, inLen, outData, outLen,
					detail::GetPtr(iv), detail::GetSize(iv), nullptr, 0,
					detail::GetPtr(outTag), detail::GetSize(outTag));
			}

			/**
			 * \brief	Decrypts structure
			 *
			 * \exception MbedTlsObj::RuntimeException
			 *
			 * \tparam	AddCtar	Data Type of the additional authentication.
			 * \tparam	IvStru 	Data Type of the IV.
			 * \tparam	TagStru	Data Type of the Tag.
			 * 					
			 * \param 		  	inData 	Input data to be decrypted.
			 * \param 		  	inLen  	Size of the input data.
			 * \param [in,out]	outData	Output decrypted data.
			 * \param 		  	outLen 	Size of the output buffer.
			 * \param 		  	iv	   	The iv.
			 * \param 		  	add	   	The additional authentication info.
			 * \param 		  	outTag 	The input tag.
			 */
			template<typename AddCtar, typename IvStru, typename TagStru>
			void Decrypt(const void* inData, const size_t inLen, void* outData, const size_t outLen,
				const IvStru& iv, const AddCtar& add, const TagStru& inTag)
			{
				Decrypt(inData, inLen, outData, outLen,
					detail::GetPtr(iv), detail::GetSize(iv), detail::GetPtr(add), detail::GetSize(add),
					detail::GetPtr(inTag), detail::GetSize(inTag));
			}

			/**
			 * \brief	Decrypts structure
			 *
			 * \exception MbedTlsObj::RuntimeException
			 *
			 * \tparam	IvStru 	Data Type of the IV.
			 * \tparam	TagStru	Data Type of the Tag.
			 * 					
			 * \param 		  	inData 	Input data to be decrypted.
			 * \param 		  	inLen  	Size of the input data.
			 * \param [in,out]	outData	Output decrypted data.
			 * \param 		  	outLen 	Size of the output buffer.
			 * \param 		  	iv	   	The iv.
			 * \param 		  	outTag 	The input tag.
			 */
			template<typename IvStru, typename TagStru>
			void Decrypt(const void* inData, const size_t inLen, void* outData, const size_t outLen,
				const IvStru& iv, const TagStru& inTag)
			{
				Decrypt(inData, inLen, outData, outLen,
					detail::GetPtr(iv), detail::GetSize(iv), nullptr, 0,
					detail::GetPtr(inTag), detail::GetSize(inTag));
			}

		protected:

			GcmBase(mbedtls_gcm_context* ptr, FreeFuncType freeFunc) noexcept :
				ObjBase(ptr, freeFunc)
			{}

			/**
			 * \brief	Encrypts data with GCM.
			 *
			 * \exception MbedTlsObj::RuntimeException
			 *
			 * \param 	   	inData 	Input data to be encrypted.
			 * \param 	   	inLen  	Size of the input data.
			 * \param [out]	outData	Output encrypted data.
			 * \param 	   	outLen 	Size of the output buffer.
			 * \param 	   	iv	   	The iv.
			 * \param 	   	ivLen  	Length of the iv.
			 * \param 	   	add	   	The additional authentication info.
			 * \param 	   	addLen 	Length of the add.
			 * \param [out]	tag	   	Output tag.
			 * \param 	   	tagLen 	Length of the tag.
			 */
			virtual void Encrypt(const void* inData, const size_t inLen, void* outData, const size_t outLen,
				const void* iv, const size_t ivLen, const void* add, const size_t addLen,
				void* tag, const size_t tagLen);

			/**
			 * \brief	Decrypts data with GCM.
			 *
			 * \exception MbedTlsObj::RuntimeException
			 *
			 * \param 		  	inData 	Input data to be decrypted.
			 * \param 		  	inLen  	Size of the input data.
			 * \param [in,out]	outData	Output decrypted data.
			 * \param 		  	dataLen	Size of the output buffer.
			 * \param 		  	iv	   	The iv.
			 * \param 		  	ivLen  	Length of the iv.
			 * \param 		  	add	   	The additional authentication info.
			 * \param 		  	addLen 	Length of the add.
			 * \param 		  	tag	   	Tag input.
			 * \param 		  	tagLen 	Length of the tag.
			 */
			virtual void Decrypt(const void* inData, const size_t inLen, void* outData, const size_t dataLen,
				const void* iv, const size_t ivLen, const void* add, const size_t addLen,
				const void* tag, const size_t tagLen);

			/**
			 * \brief	Sets GCM key
			 *
			 * \param [in,out]	ctx   	The mbed TLS GCM context.
			 * \param 		  	key   	The key.
			 * \param 		  	size  	The size of the key.
			 * \param 		  	cipher	The cipher type.
			 */
			static void SetGcmKey(mbedtls_gcm_context& ctx, const void* key, const size_t size, const GcmBase::Cipher cipher);
		};

		/**
		 * \brief	The GCM.
		 *
		 * \tparam	keySizeByte	Size of the key. Note: Only key size of 128-bit, 192-bit, 256-bit are
		 * 						supported!
		 * \tparam	cipher	   	Cipher type.
		 */
		template<size_t keySizeByte, GcmBase::Cipher cipher>
		class Gcm : public GcmBase
		{
			static_assert(keySizeByte == 16 || keySizeByte == 24 || keySizeByte == 32, "Only key size of 128-bit, 192-bit, 256-bit are supported");

		public:
			Gcm(const std::array<uint8_t, keySizeByte>& key) :
				GcmBase(sk_empty)
			{
				SetGcmKey(*Get(), key.data(), keySizeByte, cipher);
			}

			Gcm(const uint8_t(&key)[keySizeByte]) :
				GcmBase(sk_empty)
			{
				SetGcmKey(*Get(), key, keySizeByte, cipher);
			}

			Gcm(Gcm&& other) noexcept :
				GcmBase(std::forward<GcmBase>(other))
			{}

			virtual ~Gcm() 
			{}

			virtual Gcm& operator=(const Gcm& other) = delete;

			virtual Gcm& operator=(Gcm&& other)
			{
				GcmBase::operator=(std::forward<GcmBase>(other));
				return *this;
			}
		};
	}
}
