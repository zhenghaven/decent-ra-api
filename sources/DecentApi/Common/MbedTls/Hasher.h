#pragma once

#include <vector>

#include "ObjBase.h"
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

		/**
		 * \brief	Gets hash size in Byte
		 *
		 * \exception	MbedTlsObj::RuntimeException	Thrown when a nonexistent hash type is given.
		 *
		 * \tparam	type	Type of the hash.
		 *
		 * \return	The hash size in Byte.
		 */
		template<HashType type>
		inline constexpr uint8_t GetHashByteSize()
		{
			switch (type)
			{
			case HashType::SHA224:
				return (224 / BITS_PER_BYTE);
			case HashType::SHA256:
				return (256 / BITS_PER_BYTE);
			case HashType::SHA384:
				return (384 / BITS_PER_BYTE);
			case HashType::SHA512:
				return (512 / BITS_PER_BYTE);
			default:
				throw MbedTlsObj::RuntimeException("Invalid hash type is given!");
			}
		}

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
			static constexpr size_t sk_hashByteSize = GetHashByteSize<hType>();

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
	}
}
