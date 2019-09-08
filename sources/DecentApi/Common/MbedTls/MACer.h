#pragma once

#include "ObjBase.h"
#include "SafeWrappers.h"

typedef struct mbedtls_cipher_info_t mbedtls_cipher_info_t;
typedef struct mbedtls_cipher_context_t mbedtls_cipher_context_t;

namespace Decent
{
	namespace MbedTlsObj
	{
		const mbedtls_cipher_info_t& GetCipherInfo(CipherType type, uint16_t bitSize, CipherMode mode);

		class CipherBase : public ObjBase<mbedtls_cipher_context_t>
		{
		public: //static member:

			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_cipher_context_t* ptr);

		public:

			/**
			 * \brief	Constructor
			 *
			 * \param	cipherInfo	Cipher info struct from mbedTLS.
			 */
			CipherBase(const mbedtls_cipher_info_t& cipherInfo);

			/** \brief	Destructor */
			virtual ~CipherBase();

		protected:

			/** \brief	Default constructor. Construct a valid but empty cipher struct */
			CipherBase();
		};

		class CMACerBase : public CipherBase
		{
		public:
			/** \brief	Destructor */
			virtual ~CMACerBase();

		protected:
			CMACerBase() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	cipherInfo	Cipher info struct from mbedTLS.
			 * \param	key		  	The key.
			 * \param	keySize   	Size of the key. In Bytes.
			 */
			CMACerBase(const mbedtls_cipher_info_t& cipherInfo, const void* key, const size_t keySize);

			/**
			 * \brief	Updates this CMAC instance
			 *
			 * \param	data		The data.
			 * \param	dataSize	Size of the data.
			 */
			void Update(const void* data, const size_t dataSize);

			/**
			 * \brief	Finishes and retrieves the CMAC.
			 *
			 * \param [in,out]	output	The output. Must not null.
			 */
			void Finish(void* output);
		};

		template<CipherType cType, uint8_t cSize, CipherMode cMode>
		class CMACer : public CMACerBase
		{
		public: // static members:
			static constexpr uint32_t sk_cBitSize = (cSize * BITS_PER_BYTE);

			static_assert(
				sk_cBitSize == 128 ||
				sk_cBitSize == 192 ||
				sk_cBitSize == 256, "Cipher size is not supported.");

		public:
			CMACer() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \tparam	keySize	Size of the key. In Bytes.
			 * \param	key	The key.
			 */
			template<size_t keySize>
			CMACer(const SecretKeyWrap<keySize>& key) :
				CMACerBase(GetCipherInfo(cType, sk_cBitSize, cMode), key.m_key.data(), key.m_key.size())
			{}

			/** \brief	Destructor */
			virtual ~CMACer()
			{}

			/**
			 * \brief	Calculate CMAC in batched mode.
			 *
			 * \param [out]	output	The output.
			 * \param 	   	list  	The list of pointers and sizes.
			 */
			void Batched(std::array<uint8_t, cSize>& output, const std::vector<DataListItem>& list)
			{
				return BatchedInternal(output.data(), list.data(), list.size());
			}

			/**
			 * \brief	Calculate CMAC in batched mode.
			 *
			 * \param [out]	output	The output.
			 * \param 	   	list  	The list of pointers and sizes.
			 */
			void Batched(uint8_t(&output)[cSize], const std::vector<DataListItem>& list)
			{
				return BatchedInternal(output, list.data(), list.size());
			}

			/**
			 * \brief	Calculate CMAC in batched mode.
			 *
			 * \tparam	listLen	Type of the list length.
			 * \param [out]	output	The output.
			 * \param 	   	list  	The list of pointers and sizes.
			 */
			template<size_t listLen>
			void Batched(std::array<uint8_t, cSize>& output, const std::array<DataListItem, listLen>& list)
			{
				return BatchedInternal(output.data(), list.data(), listLen);
			}

			/**
			 * \brief	Calculate CMAC in batched mode.
			 *
			 * \tparam	listLen	Type of the list length.
			 * \param [out]	output	The output.
			 * \param 	   	list  	The list of pointers and sizes.
			 */
			template<size_t listLen>
			void Batched(uint8_t(&output)[cSize], const std::array<DataListItem, listLen>& list)
			{
				return BatchedInternal(output, list.data(), listLen);
			}

			/**
			 * \brief	Calculate the CMAC of a single piece of data.
			 *
			 * \tparam	Container	Type of the container.
			 * \param 		  	data  	The data.
			 * \param [out]	output	The output.
			 */
			template<typename Container>
			void Calc(std::array<uint8_t, cSize>& output, const Container& data)
			{
				Update(detail::GetPtr(data), detail::GetSize(data));
				Finish(output.data());
			}

			template<typename Container>
			void Calc(uint8_t(&output)[cSize], const Container& data)
			{
				Update(detail::GetPtr(data), detail::GetSize(data));
				Finish(output);
			}

			/**
			 * \brief	Calculate CMAC of a list of data (more than one) in batched mode, with helper to setup
			 * 			the batch list. This function only accept container types for input data, so that it
			 * 			can automatically get the pointers and sizes.
			 *
			 * \tparam	Arg1	Type of the argument 1.
			 * \tparam	Arg2	Type of the argument 2.
			 * \tparam	Args	Type of the arguments. NOTE: only continuous containers (i.e. C array,
			 * 					std::array, std::vector, std::basic_string) are accepted.
			 * \param [in,out]	output	The output.
			 * \param 		  	arg1  	The first argument.
			 * \param 		  	arg2  	The second argument.
			 * \param 		  	args  	Variable arguments providing the arguments.
			 */
			template<class Arg1, class Arg2, class... Args>
			void Calc(std::array<uint8_t, cSize>& output, const Arg1& arg1, const Arg2& arg2, const Args&... args)
			{
				Batched(output, detail::ConstructDataList(arg1, arg2, args...));
			}

			template<class Arg1, class Arg2, class... Args>
			void Calc(uint8_t(&output)[cSize], const Arg1& arg1, const Arg2& arg2, const Args&... args)
			{
				Batched(output, detail::ConstructDataList(arg1, arg2, args...));
			}

		private:

			/**
			 * \brief	Internal method to calculate CMAC in batched mode.
			 *
			 * \param [out]	output  	The output.
			 * \param 	   	dataList	List of data.
			 * \param 	   	listLen 	Length of the list.
			 */
			void BatchedInternal(void* output, const DataListItem* dataList, size_t listLen)
			{
				// Used internally, assume dataList is not null, AND output has enough memory size.
				
				for (size_t i = 0; i < listLen; ++i)
				{
					Update(dataList[i].m_ptr, dataList[i].m_size);
				}

				Finish(output);
			}
		};
	}
}
