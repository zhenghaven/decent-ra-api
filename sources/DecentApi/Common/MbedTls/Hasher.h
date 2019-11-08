#pragma once

#include <vector>

#include "ObjBase.h"
#include "SafeWrappers.h"
#include "DataSizeGetters.h"
#include "MbedTlsException.h"

struct mbedtls_md_info_t; 
typedef struct mbedtls_md_context_t mbedtls_md_context_t;

namespace Decent
{
	namespace MbedTlsObj
	{
		/**
		 * \brief	Gets MbedTls's message digest information struct
		 *
		 * \exception	MbedTlsObj::RuntimeException	Thrown when a nonexistent hash type is given.
		 *
		 * \param	type	The type of hash algorithm.
		 *
		 * \return	A reference to MbedTls's const mbedtls_md_info_t.
		 */
		const mbedtls_md_info_t& GetMsgDigestInfo(HashType type);

		/** \brief	A hash calculator. */
		class MsgDigestBase : public ObjBase<mbedtls_md_context_t>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_md_context_t* ptr);

		public:

			MsgDigestBase(const mbedtls_md_info_t& mdInfo, bool needHMac);

			/** \brief	Destructor */
			virtual ~MsgDigestBase();

			/**
			 * \brief	Query if the pointers to objects held by this object is null
			 *
			 * \return	True if null, false if not.
			 */
			using ObjBase::IsNull;

		protected:

			MsgDigestBase();

			MsgDigestBase(MsgDigestBase&& rhs);

			MsgDigestBase(const MsgDigestBase& rhs) = delete;
		};
		
		class HasherBase : public MsgDigestBase
		{
		public:

			/** \brief	Destructor */
			virtual ~HasherBase();

		protected:

			HasherBase() = delete;

			/**
			 * \brief	Constructor. mbedtls_md_starts is called here.
			 *
			 * \param	mdInfo	Information describing the md.
			 */
			HasherBase(const mbedtls_md_info_t& mdInfo);

			/**
			 * \brief	Updates the calculation with the given data.
			 *
			 * \param	data		The data.
			 * \param	dataSize	Size of the data.
			 */
			void Update(const void* data, const size_t dataSize);

			/**
			 * \brief	Finishes the hash calculation and get the result.
			 *
			 * \param [out]	output	The output. Must not null! And make sure to check the buffer size is big
			 * 						enough before calling this method!
			 */
			void Finish(void* output);
		};

		template<HashType hType>
		class Hasher : public HasherBase
		{
		public: //static members:
			static constexpr size_t sk_hashByteSize = GetHashByteSize(hType);

		public:
			Hasher() :
				HasherBase(GetMsgDigestInfo(hType))
			{}

			virtual ~Hasher()
			{}

			/**
			 * \brief	Calculate hash of a list of data in batched mode.
			 *
			 * \tparam	listLen	Type of the list length.
			 * \param [out]	output	The output.
			 * \param 	   	list  	The list of pointers and sizes.
			 */
			template<size_t listLen>
			void Batched(std::array<uint8_t, sk_hashByteSize>& output, const std::array<DataListItem, listLen>& list)
			{
				return BatchedInternal(output.data(), list.data(), listLen);
			}

			template<size_t listLen>
			void Batched(uint8_t(&output)[sk_hashByteSize], const std::array<DataListItem, listLen>& list)
			{
				return BatchedInternal(output, list.data(), listLen);
			}

			void Batched(std::array<uint8_t, sk_hashByteSize>& output, const std::vector<DataListItem>& list)
			{
				return BatchedInternal(output.data(), list.data(), list.size());
			}

			void Batched(uint8_t(&output)[sk_hashByteSize], const std::vector<DataListItem>& list)
			{
				return BatchedInternal(output, list.data(), list.size());
			}

			/**
			 * \brief	Calculate hash of a single piece of data.
			 *
			 * \tparam	Container	Type of the container.
			 * \param [in,out]	output	The output.
			 * \param 		  	data  	The data.
			 */
			template<typename Container>
			void Calc(std::array<uint8_t, sk_hashByteSize>& output, const Container& data)
			{
				Update(detail::GetPtr(data), detail::GetSize(data));
				Finish(output.data());
			}

			template<typename Container>
			void Calc(uint8_t(&output)[sk_hashByteSize], const Container& data)
			{
				Update(detail::GetPtr(data), detail::GetSize(data));
				Finish(output);
			}

			/**
			 * \brief	Calculate hash of a list of data (more than one) in batched mode, with helper to
			 * 			setup the batch list. This function only accept container types for input data, so
			 * 			that it can automatically get the pointers and sizes.
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
			void Calc(std::array<uint8_t, sk_hashByteSize>& output, const Arg1& arg1, const Arg2& arg2, const Args&... args)
			{
				Batched(output, detail::ConstructDataList(arg1, arg2, args...));
			}

			template<class Arg1, class Arg2, class... Args>
			void Calc(uint8_t(&output)[sk_hashByteSize], const Arg1& arg1, const Arg2& arg2, const Args&... args)
			{
				Batched(output, detail::ConstructDataList(arg1, arg2, args...));
			}

		private:

			/**
			 * \brief	Internal method to calculate MAC in batched mode.
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

		class HMACerBase : public MsgDigestBase
		{
		public:
			/** \brief	Destructor */
			virtual ~HMACerBase();

		protected:
			HMACerBase() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \param	cipherInfo	Cipher info struct from mbedTLS.
			 * \param	key		  	The key.
			 * \param	keySize   	Size of the key. In Bytes.
			 */
			HMACerBase(const mbedtls_md_info_t& mdInfo, const void* key, const size_t keySize);

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

		template<HashType hType>
		class HMACer : public HMACerBase
		{
		public: //static members:
			static constexpr size_t sk_hashByteSize = GetHashByteSize(hType);

		public:
			HMACer() = delete;

			/**
			 * \brief	Constructor
			 *
			 * \tparam	keySize	Size of the key. In Bytes.
			 * \param	key	The key.
			 */
			template<size_t keySize>
			HMACer(const SecretKeyWrap<keySize>& key) :
				HMACerBase(GetMsgDigestInfo(hType), key.m_key.data(), key.m_key.size())
			{}

			/** \brief	Destructor */
			virtual ~HMACer()
			{}

			/**
			 * \brief	Calculate HMAC in batched mode.
			 *
			 * \param [out]	output	The output.
			 * \param 	   	list  	The list of pointers and sizes.
			 */
			template<typename containerType,
				typename std::enable_if<detail::StatCtnWithSize<containerType, sk_hashByteSize>::value, int>::type = 0>
			void Batched(containerType& output, const std::vector<DataListItem>& list)
			{
				return BatchedInternal(detail::GetPtr(output), list.data(), list.size());
			}

			/**
			 * \brief	Calculate HMAC in batched mode.
			 *
			 * \tparam	listLen	Type of the list length.
			 * \param [out]	output	The output.
			 * \param 	   	list  	The list of pointers and sizes.
			 */
			template<typename containerType,
				typename std::enable_if<detail::StatCtnWithSize<containerType, sk_hashByteSize>::value, int>::type = 0,
				size_t listLen>
			void Batched(containerType& output, const std::array<DataListItem, listLen>& list)
			{
				return BatchedInternal(detail::GetPtr(output), list.data(), listLen);
			}

			/**
			 * \brief	Calculate the HMAC of a single piece of data.
			 *
			 * \tparam	Container	Type of the container.
			 * \param 		  	data  	The data.
			 * \param [out]	output	The output.
			 */
			template<typename ResContainerType, typename DataContainerType,
				typename std::enable_if<detail::StatCtnWithSize<ResContainerType, sk_hashByteSize>::value &&
					detail::ContainerPrpt<DataContainerType>::sk_isSprtCtn, int>::type = 0>
			void Calc(ResContainerType& output, const DataContainerType& data)
			{
				Update(detail::GetPtr(data), detail::GetSize(data));
				Finish(detail::GetPtr(output));
			}

			/**
			 * \brief	Calculate HMAC of a list of data (more than one) in batched mode, with helper to setup
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
			template<typename ResContainerType,
				typename std::enable_if<detail::StatCtnWithSize<ResContainerType, sk_hashByteSize>::value, int>::type = 0,
				class Arg1, class Arg2, class... Args>
			void Calc(ResContainerType& output, const Arg1& arg1, const Arg2& arg2, const Args&... args)
			{
				Batched(output, detail::ConstructDataList(arg1, arg2, args...));
			}

		private:

			/**
			 * \brief	Internal method to calculate HMAC in batched mode.
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
