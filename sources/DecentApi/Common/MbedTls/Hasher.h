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
		const mbedtls_md_info_t& GetMdInfo(HashType type);

		/**
		 * \brief	Gets hash size in Byte
		 *
		 * \exception	MbedTlsObj::RuntimeException	Thrown when a nonexistent hash type is given.
		 *
		 * \param	type	The type of hash algorithm.
		 *
		 * \return	The hash size in Byte.
		 */
		inline uint8_t GetHashSizeByte(HashType type)
		{
			switch (type)
			{
			case HashType::SHA224:
				return (224 / 8);
			case HashType::SHA256:
				return (256 / 8);
			case HashType::SHA384:
				return (384 / 8);
			case HashType::SHA512:
				return (512 / 8);
			default:
				throw MbedTlsObj::RuntimeException("Invalid hash type is given!");
			}
		}

		/** \brief	A hash calculator. */
		class Hasher : public ObjBase<mbedtls_md_context_t>
		{
		public:
			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_md_context_t* ptr);

			/**
			 * \brief	Calculates hash for a single item.
			 *
			 * \exception	MbedTlsObj::RuntimeException	Thrown when a error happened during calculation.
			 *
			 * \tparam	hashType	Type of the hash algorithm.
			 * \tparam	InType		Data type of the input.
			 * \tparam	OutType		Data type of the output hash.
			 * \param 		  	input 	The input data.
			 * \param [in,out]	output	The output hash.
			 */
			template<HashType hashType, typename InType, typename OutType>
			static void Calc(const InType& input, OutType& output)
			{
				Calc(GetMdInfo(hashType), detail::GetPtr(input), detail::GetSize(input), detail::GetPtr(output), detail::GetSize(output));
			}

			/**
			 * \brief	Calculates hash for a single item.
			 *
			 * \exception	MbedTlsObj::RuntimeException	Thrown when a error happened during calculation.
			 *
			 * \tparam	hashType	Type of the hash algorithm.
			 * \tparam	OutType		Data type of the output hash.
			 * \param 		  	input 	The input data.
			 * \param 		  	inSize	Size of the input data.
			 * \param [in,out]	output	The output hash.
			 */
			template<HashType hashType, typename OutType>
			static void Calc(const void* input, const size_t inSize, OutType& output)
			{
				Calc(GetMdInfo(hashType), input, inSize, detail::GetPtr(output), detail::GetSize(output));
			}

			/**
			 * \brief	Batched calculates hash for a list of data. The datalist is provided in std::array,
			 * 			which means the size of the list is determined at compiled time. 
			 *
			 * \exception	MbedTlsObj::RuntimeException	Thrown when a error happened during calculation.
			 *
			 * \tparam	hashType   	Type of the hash algorithm.
			 * \tparam	dataListLen	Length of the data list.
			 * \tparam	OutType	   	Data type of the output hash.
			 * \param 		  	dataList	List of DataListItem. Please also checkout the definition of
			 * 								struct DataListItem.
			 * \param [in,out]	output  	The output hash.
			 */
			template<HashType hashType, size_t dataListLen, typename OutType>
			static void BatchedCalc(const std::array<DataListItem, dataListLen>& dataList, OutType& output)
			{
				Hasher().BatchedCalcInternal<hashType>(dataList, output);
			}

			/**
			* \brief	Batched calculates hash for a list of data. The datalist is provided in std::vector,
			* 			so that the size of the list can be determined at runtime.
			*
			* \exception	MbedTlsObj::RuntimeException	Thrown when a error happened during calculation.
			*
			* \tparam	hashType	Type of the hash algorithm.
			* \tparam	OutType		Data type of the output hash.
			* \param 		  	dataList	List of DataListItem. Please also checkout the definition of
			* 								struct DataListItem.
			* \param [in,out]	output  	The output hash.
			*/
			template<HashType hashType, typename OutType>
			static void BatchedCalc(const std::vector<DataListItem>& dataList, OutType& output)
			{
				Hasher().BatchedCalcInternal<hashType>(dataList, output);
			}

			/**
			 * \brief	Batched calculates hash for any number of array type objects (i.e. C array (not
			 * 			pointer!), std::array, std::vector, std::basic_string).
			 *
			 * \tparam	hashType	Type of the hash algorithm.
			 * \tparam	OutT		Data type of the output hash.
			 * \tparam	Args		Type of the arguments.
			 * \param [in,out]	output	The output.
			 * \param 		  	args  	Variable arguments providing the arguments.
			 */
			template<HashType hashType, typename OutT, class... Args>
			static void ArrayBatchedCalc(OutT& output, const Args&... args)
			{
				BatchedCalc<hashType>(detail::ConstructDataList(args...), output);
			}

		private:

			/**
			 * \brief	Default constructor that constructs Hasher object. This is only needed for batched
			 * 			calculation. However, all member methods are private, instead, static functions are
			 * 			exposed to be used for hash calculations. Please use static member functions.
			 */
			Hasher();

			Hasher(const Hasher& rhs) = delete; //There is no reason to copy this object;

			Hasher(Hasher&& rhs) = delete; //There is no reason to move this object;

			/** \brief	Destructor */
			virtual ~Hasher();

			/**
			 * \brief	Batched calculates hash for a list of data. The datalist is provided in std::array,
			 * 			which means the size of the list is determined at compiled time.  
			 *
			 * \exception	MbedTlsObj::RuntimeException	Thrown when a error happened during calculation.
			 *
			 * \tparam	hashType   	Type of the hash algorithm.
			 * \tparam	dataListLen	Length of the data list.
			 * \tparam	OutType	   	Data type of the output hash.
			 * \param 		  	dataList	List of DataListItem. Please also checkout the definition of
			 * 								struct DataListItem.
			 * \param [in,out]	output  	The output hash.
			 */
			template<HashType hashType, size_t dataListLen, typename OutType>
			void BatchedCalcInternal(const std::array<DataListItem, dataListLen>& dataList, OutType& output)
			{
				BatchedCalcInternal(GetMdInfo(hashType), dataList.data(), dataListLen, detail::GetPtr(output), detail::GetSize(output));
			}

			/**
			 * \brief	Batched calculates hash for a list of data. The datalist is provided in std::vector,
			 * 			so that the size of the list can be determined at runtime.
			 *
			 * \exception	MbedTlsObj::RuntimeException	Thrown when a error happened during calculation.
			 *
			 * \tparam	hashType	Type of the hash algorithm.
			 * \tparam	OutType		Data type of the output hash.
			 * \param 		  	dataList	List of DataListItem. Please also checkout the definition of
			 * 								struct DataListItem.
			 * \param [in,out]	output  	The output hash.
			 */
			template<HashType hashType, typename OutType>
			void BatchedCalcInternal(const std::vector<DataListItem>& dataList, OutType& output)
			{
				BatchedCalcInternal(GetMdInfo(hashType), dataList.data(), dataList.size(), detail::GetPtr(output), detail::GetSize(output));
			}

		private:

			/**
			 * \brief	Batched calculates hash for a list of data. 
			 *
			 * \exception	MbedTlsObj::RuntimeException	Thrown when a error happened during calculation.
			 *
			 * \param 		  	mdInfo  	MbedTls's mbedtls_md_info_t.
			 * \param 		  	dataList	List of data.
			 * \param 		  	listLen 	Length of the list.
			 * \param [in,out]	output  	The output buffer.
			 * \param 		  	outSize 	Size of the output.
			 */
			void BatchedCalcInternal(const mbedtls_md_info_t& mdInfo, const DataListItem* dataList, size_t listLen, void* output, const size_t outSize);

			/**
			 * \brief	Calculates hash for a single item.
			 *
			 * \exception	MbedTlsObj::RuntimeException	Thrown when a error happened during calculation.
			 *
			 * \param 		  	mdInfo 	MbedTls's mbedtls_md_info_t.
			 * \param 		  	input  	The input buffer.
			 * \param 		  	inSize 	Size of the input.
			 * \param [in,out]	output 	The output buffer.
			 * \param 		  	outSize	Size of the output.
			 */
			static void Calc(const mbedtls_md_info_t& mdInfo, const void* input, const size_t inSize, void* output, const size_t outSize);

		};
		
	}
}
