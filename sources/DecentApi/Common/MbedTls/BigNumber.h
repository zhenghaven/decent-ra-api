#pragma once

#include "ObjBase.h"

#include <cstdint>
#include <array>
#include <vector>

typedef struct mbedtls_mpi mbedtls_mpi;
typedef uint64_t mbedtls_mpi_uint;

namespace Decent
{
	namespace MbedTlsObj
	{
		class ConstBigNumber;

		class BigNumber : public ObjBase<mbedtls_mpi>
		{
		public: //static members:

			/**
			* \brief	Function that frees MbedTLS object and delete the pointer.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void FreeObject(mbedtls_mpi* ptr);

			/**
			* \brief	Generates a random number with specific size.
			*
			* \param	size	The size.
			*
			* \return	The random number.
			*/
			static BigNumber Rand(size_t size);

			/**
			 * \brief	Converts a byte to a hexadecimal string
			 *
			 * \param	num	Byte.
			 *
			 * \return	a hexadecimal string.
			 */
			static std::string ToHexStr(uint8_t num) noexcept;

			/**
			 * \brief	Converts this object to a hexadecimal string in big endian
			 *
			 * \param	ptr		  	The pointer.
			 * \param	size	  	The size.
			 * \param	parameter3	Indicate it is a big endian string.
			 *
			 * \return	a hexadecimal string.
			 */
			static std::string ToHexStr(const void * ptr, const size_t size, const BigEndian&);

			/**
			 * \brief	Converts this object to a hexadecimal string in big endian
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	input	  	The input.
			 * \param	parameter2	Indicate input is a struct.
			 * \param	parameter3	Indicate it is a big endian string.
			 *
			 * \return	a hexadecimal string.
			 */
			template<typename T>
			static std::string ToHexStr(const T& input, const StructIn&, const BigEndian&)
			{
				return ToHexStr(&input, sizeof(T), sk_bigEndian);
			}

		public:
			BigNumber() = delete;

			/**
			* \brief	Constructor that generate a big number. Nothing has been filled-in.
			*
			* \param	parameter1	The dummy variable that indicates the need for generating a big number object.
			*/
			BigNumber(const Empty&);

			/**
			 * \brief	Construct a big number by copy an existing binary data in little-endian.
			 *
			 * \param	ptr 	The pointer.
			 * \param	size	The size.
			 */
			BigNumber(const void* ptr, const size_t size);

			/**
			 * \brief	Construct a big number by copy an existing binary data in little-endian.
			 *
			 * \tparam	T   	Generic type parameter.
			 * \tparam	size	Size of the array.
			 * \param	in	The input.
			 */
			template<typename T, size_t size>
			BigNumber(const std::array<T, size>& in) :
				BigNumber(in.data(), size * sizeof(T))
			{}

			/**
			 * \brief	Construct a big number by copy an existing binary data in little-endian.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	in	The input.
			 */
			template<typename T>
			BigNumber(const std::vector<T>& in) :
				BigNumber(in.data(), in.size() * sizeof(T))
			{}

			/**
			 * \brief	Construct a big number by copy an existing binary data in little-endian.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	in		  	The input.
			 * \param	parameter2	Indicate the input is a struct.
			 */
			template<typename T>
			BigNumber(const T& in, const StructIn&) :
				BigNumber(&in, sizeof(T))
			{}

			/**
			 * \brief	Construct a big number by copy an existing binary data in big-endian.
			 *
			 * \param	ptr		  	The pointer.
			 * \param	size	  	The size.
			 * \param	parameter3	Indicate the input is in big endian.
			 */
			BigNumber(const void* ptr, const size_t size, const BigEndian&);

			/**
			 * \brief	Construct a big number by copy an existing binary data in big-endian.
			 *
			 * \tparam	T   	Generic type parameter.
			 * \tparam	size	Size of the array.
			 * \param	in		  	The input.
			 * \param	parameter2	Indicate the input is in big endian.
			 */
			template<typename T, size_t size>
			BigNumber(const std::array<T, size>& in, const BigEndian&) :
				BigNumber(in.data(), size * sizeof(T), sk_bigEndian)
			{}

			/**
			 * \brief	Construct a big number by copy an existing binary data in big-endian.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	in		  	The input.
			 * \param	parameter2	Indicate the input is in big endian.
			 */
			template<typename T>
			BigNumber(const std::vector<T>& in, const BigEndian&) :
				BigNumber(in.data(), in.size() * sizeof(T), sk_bigEndian)
			{}

			/**
			 * \brief	Construct a big number by copy an existing binary data in big-endian.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	in		  	The input.
			 * \param	parameter2	Indicate the input is a struct.
			 * \param	parameter3	Indicate the input is in big endian.
			 */
			template<typename T>
			BigNumber(const T& in, const StructIn&, const BigEndian&) :
				BigNumber(&in, sizeof(T), sk_bigEndian)
			{}

			/**
			* \brief	Move constructor
			*
			* \param [in,out]	other	The other instance.
			*/
			BigNumber(BigNumber&& other) noexcept :
				ObjBase(std::forward<ObjBase>(other))
			{}

			/**
			 * \brief	Construct a big number by copy an existing mbed TLS big number.
			 *
			 * \param	rhs	The right hand side.
			 */
			BigNumber(const mbedtls_mpi& rhs);

			/**
			 * \brief	Copy constructor
			 *
			 * \param	rhs	The right hand side.
			 */
			BigNumber(const BigNumber& rhs);

			/**
			 * \brief	Constructor a big number by copy an existing const big number.
			 *
			 * \param	rhs	The right hand side.
			 */
			BigNumber(const ConstBigNumber& rhs);

			/** \brief	Destructor */
			virtual ~BigNumber() noexcept {}

			/**
			 * \brief	Swaps this instance with the given right hand side var
			 *
			 * \param [in,out]	rhs	The right hand side var.
			 */
			virtual void Swap(BigNumber& rhs) noexcept
			{
				ObjBase::Swap(rhs);
			}

			BigNumber& operator=(const BigNumber& rhs);

			/**
			 * \brief	Compares this const BigNumber&amp; object to another to determine their relative
			 * 			ordering
			 *
			 * \param	rhs	The constant big number&amp; to compare to this object.
			 *
			 * \return	Negative if 'rhs' is less than this instance, 0 if they are equal, or positive if it is greater.
			 */
			int Compare(const BigNumber& rhs) const noexcept;

			/**
			 * \brief	Addition operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator+(const BigNumber& rhs) const;

			/**
			 * \brief	Addition operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator+(int64_t rhs) const;

			/**
			 * \brief	Subtraction operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator-(const BigNumber& rhs) const;

			/**
			 * \brief	Subtraction operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator-(int64_t rhs) const;

			/**
			 * \brief	Multiplication operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator*(const BigNumber& rhs) const;

			/**
			 * \brief	Multiplication operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator*(uint64_t rhs) const;

			/**
			 * \brief	Division operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator/(const BigNumber& rhs) const;

			/**
			 * \brief	Division operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator/(int64_t rhs) const;

			/**
			 * \brief	Modulus operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator%(const BigNumber& rhs) const;

			/**
			 * \brief	Modulus operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			uint64_t operator%(int64_t rhs) const;

			//BigNumber operator<<(size_t count) const;

			//BigNumber operator>>(size_t count) const;

			/**
			* \brief	Equal comparison operator
			*
			* \param	rhs	The right hand side.
			*
			* \return	True if the first parameter is equal to the second.
			*/
			bool operator==(const BigNumber& rhs) const;

			/**
			 * \brief	Less-than comparison operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is less than the second.
			 */
			bool operator<(const BigNumber& rhs) const;

			/**
			 * \brief	Less-than-or-equal comparison operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is less than or equal to the second.
			 */
			bool operator<=(const BigNumber& rhs) const;

			/**
			 * \brief	Greater-than comparison operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is greater than to the second.
			 */
			bool operator>(const BigNumber& rhs) const;

			/**
			 * \brief	Greater-than-or-equal comparison operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is greater than or equal to the second.
			 */
			bool operator>=(const BigNumber& rhs) const;

			/**
			* \brief	Gets the size of this big number in Bytes.
			*
			* \return	The size.
			*/
			size_t GetSize() const;

			/**
			* \brief	Gets the size of this big number in bits.
			*
			* \return	The size.
			*/
			size_t GetBitSize() const;

			/**
			 * \brief	Addition assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator+=(const BigNumber& rhs);

			/**
			 * \brief	Addition assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator+=(int64_t rhs);

			/**
			 * \brief	Subtraction assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator-=(const BigNumber& rhs);

			/**
			 * \brief	Subtraction assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator-=(int64_t rhs);

			/**
			 * \brief	Multiplication assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator*=(const BigNumber& rhs);

			/**
			 * \brief	Multiplication assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator*=(uint64_t rhs);

			/**
			 * \brief	Division assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator/=(const BigNumber& rhs);

			/**
			 * \brief	Division assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator/=(int64_t rhs);

			/**
			 * \brief	Modulus assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator%=(const BigNumber& rhs);

			/**
			 * \brief	Modulus assignment operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator%=(int64_t rhs);

			/**
			 * \brief	Bitwise left shift assignment operator
			 *
			 * \param	count	Number of.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator<<=(size_t count);

			/**
			 * \brief	Bitwise right shift assignment operator
			 *
			 * \param	count	Number of.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator>>=(size_t count);

			/**
			* \brief	Converts this big number to a little endian binary
			*
			* \param [in,out]	out 	If non-null, the output address.
			* \param 		  	size	The size of the output buffer.
			*/
			void ToBinary(void* out, const size_t size) const;

			/**
			 * \brief	Convert this object into a binary representation
			 *
			 * \tparam	T   	Generic type parameter.
			 * \tparam	size	Size of the array.
			 * \param [in,out]	out	The output.
			 */
			template<typename T, size_t size>
			void ToBinary(std::array<T, size>& out) const
			{
				constexpr size_t totalSize = size * sizeof(T);
				return ToBinary(out.data(), totalSize);
			}

			/**
			 * \brief	Convert this object into a binary representation
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	out	The output.
			 */
			template<typename T>
			void ToBinary(std::vector<T>& out) const
			{
				return ToBinary(out.data(), out.size() * sizeof(T));
			}

			/**
			* \brief	Converts this big number to a little endian binary
			*
			* \param [in,out]	out 	The reference to the output space.
			*
			* \return	Whether or not the conversion is successful.
			*/
			template<typename T>
			void ToBinary(T& out, const StructIn&) const
			{
				return ToBinary(&out, sizeof(T));
			}

			/**
			 * \brief	Converts this big number to a big endian binary
			 *
			 * \param [in,out]	out		  	If non-null, the output address.
			 * \param 		  	size	  	The size of the output buffer.
			 * \param 		  	parameter3	Indicate the output should be in big endian.
			 */
			void ToBinary(void* out, const size_t size, const BigEndian&) const;

			/**
			 * \brief	Convert this object into a binary representation
			 *
			 * \tparam	T   	Generic type parameter.
			 * \tparam	size	Size of the array.
			 * \param [in,out]	out		  	The output.
			 * \param 		  	parameter2	Indicate the output should be in big endian.
			 */
			template<typename T, size_t size>
			void ToBinary(std::array<T, size>& out, const BigEndian&) const
			{
				constexpr size_t totalSize = size * sizeof(T);
				return ToBinary(out.data(), totalSize, sk_bigEndian);
			}

			/**
			 * \brief	Convert this object into a binary representation
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	out		  	The output.
			 * \param 		  	parameter2	Indicate the output should be in big endian.
			 */
			template<typename T>
			void ToBinary(std::vector<T>& out, const BigEndian&) const
			{
				return ToBinary(out.data(), out.size() * sizeof(T), sk_bigEndian);
			}

			/**
			 * \brief	Converts this big number to a big endian binary
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	out		  	The reference to the output buffer.
			 * \param 		  	parameter2	Indicate the output buffer is a struct.
			 * \param 		  	parameter3	Indicate the output should be in big endian.
			 */
			template<typename T>
			void ToBinary(T& out, const StructIn&, const BigEndian&) const
			{
				return ToBinary(&out, sizeof(T), sk_bigEndian);
			}

			/**
			 * \brief	Converts this object to a big endian hexadecimal string
			 *
			 * \return	This object as a std::string.
			 */
			std::string ToBigEndianHexStr() const;

		};

		class ConstBigNumber : public ObjBase<mbedtls_mpi>
		{
		public: //static members:

				/**
				* \brief	Function that only delete the pointer.
				*
				* \param [in,out]	ptr	If non-null, the pointer.
				*/
			static void FreeStruct(mbedtls_mpi* ptr);

		public:
			ConstBigNumber() = delete;

			/**
			 * \brief	Constructor that accept a reference to BigNumber object, thus, this instance doesn't
			 * 			has the ownership.
			 *
			 * \param	ref	The reference.
			 */
			ConstBigNumber(const BigNumber& ref) noexcept;

			/**
			* \brief	Constructor that accept a reference to mbedtls_mpi object, thus, this instance doesn't
			* 			has the ownership.
			*
			* \param [in,out]	ref	The reference.
			*/
			ConstBigNumber(mbedtls_mpi& ref) noexcept;

			/**
			* \brief	Construct a big number by referencing an existing binary data in little-endian.
			* 			NOTE: REFERENCE ONLY, there is no copy operation, so make sure the referenced data's life time!
			*
			* \param	ptr 	The pointer.
			* \param	size	The size.
			*/
			ConstBigNumber(const void* ptr, const size_t size);

			/**
			 * \brief	Construct a big number by referencing an existing binary data in little-endian.
			 * 			NOTE: REFERENCE ONLY, there is no copy operation, so make sure the referenced data's life time!
			 *
			 * \tparam	T   	Generic type parameter.
			 * \tparam	size	Size of the array.
			 * \param	in	The input.
			 */
			template<typename T, size_t size>
			ConstBigNumber(const std::array<T, size>& in) noexcept :
				ConstBigNumber(in.data(), size * sizeof(T), sk_gen)
			{
				static_assert(!(totalSize % sizeof(mbedtls_mpi_uint)), "The size of the given big number must be a factor of 8-Byte (64-bit). ");
			}

			/**
			 * \brief	Construct a big number by referencing an existing binary data in little-endian.
			 * 			NOTE: REFERENCE ONLY, there is no copy operation, so make sure the referenced data's life time!
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	in	The input.
			 */
			template<typename T>
			ConstBigNumber(const std::vector<T>& in) :
				ConstBigNumber(in.data(), in.size() * sizeof(T))
			{}

			/**
			 * \brief	Construct a big number by referencing an existing binary data in little-endian.
			 * 			NOTE: REFERENCE ONLY, there is no copy operation, so make sure the referenced data's life time!
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	in		  	The input.
			 * \param	parameter2	Indicate the input is a struct.
			 */
			template<typename T>
			ConstBigNumber(const T& in, const StructIn&)  noexcept :
				ConstBigNumber(&in, sizeof(T), sk_gen)
			{
				static_assert(!(sizeof(T) % sizeof(mbedtls_mpi_uint)), "The size of the given big number must be a factor of 8-Byte (64-bit). ");
			}

			/**
			* \brief	Move constructor
			*
			* \param [in,out]	other	The other instance.
			*/
			ConstBigNumber(ConstBigNumber&& other) noexcept :
			ObjBase(std::forward<ObjBase>(other))
			{}

			ConstBigNumber(const ConstBigNumber& rhs) = delete;

			/** \brief	Destructor */
			virtual ~ConstBigNumber() noexcept {}

			/**
			* \brief	Swaps this instance with the given right hand side var
			*
			* \param [in,out]	rhs	The right hand side var.
			*/
			virtual void Swap(ConstBigNumber& rhs) noexcept
			{
				ObjBase::Swap(rhs);
			}

			/**
			 * \brief	Compares this const ConstBigNumber&amp; object to another to determine their relative
			 * 			ordering
			 *
			 * \param	rhs	The constant big number&amp; to compare to this object.
			 *
			 * \return	Negative if 'rhs' is less than this, 0 if they are equal, or positive if it is greater.
			 */
			int Compare(const ConstBigNumber& rhs) const noexcept;

			/**
			 * \brief	Addition operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator+(const ConstBigNumber& rhs) const;

			/**
			 * \brief	Addition operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator+(int64_t rhs) const;

			/**
			 * \brief	Subtraction operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator-(const ConstBigNumber& rhs) const;

			/**
			 * \brief	Subtraction operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator-(int64_t rhs) const;

			/**
			 * \brief	Multiplication operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator*(const ConstBigNumber& rhs) const;

			/**
			 * \brief	Multiplication operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator*(uint64_t rhs) const;

			/**
			 * \brief	Division operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator/(const ConstBigNumber& rhs) const;

			/**
			 * \brief	Division operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator/(int64_t rhs) const;

			/**
			 * \brief	Modulus operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator%(const ConstBigNumber& rhs) const;

			/**
			 * \brief	Modulus operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			uint64_t operator%(int64_t rhs) const;

			//BigNumber operator<<(size_t count) const;

			//BigNumber operator>>(size_t count) const;

			/**
			 * \brief	Equal comparison operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is equal to the second.
			 */
			bool operator==(const ConstBigNumber& rhs) const;

			/**
			 * \brief	Less-than comparison operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is less than the second.
			 */
			bool operator<(const ConstBigNumber& rhs) const;

			/**
			 * \brief	Less-than-or-equal comparison operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is less than or equal to the second.
			 */
			bool operator<=(const ConstBigNumber& rhs) const;

			/**
			 * \brief	Greater-than comparison operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is greater than to the second.
			 */
			bool operator>(const ConstBigNumber& rhs) const;

			/**
			 * \brief	Greater-than-or-equal comparison operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is greater than or equal to the second.
			 */
			bool operator>=(const ConstBigNumber& rhs) const;

			/**
			* \brief	Gets the size of this big number in Bytes.
			*
			* \return	The size.
			*/
			size_t GetSize() const;

			/**
			* \brief	Gets the size of this big number in bits.
			*
			* \return	The size.
			*/
			size_t GetBitSize() const;


			/**
			* \brief	Converts this big number to a little endian binary
			*
			* \param [in,out]	out 	If non-null, the output address.
			* \param 		  	size	The size of the output buffer.
			*/
			void ToBinary(void* out, const size_t size) const;

			/**
			 * \brief	Convert this object into a little endian binary
			 *
			 * \tparam	T   	Generic type parameter.
			 * \tparam	size	Size of the array.
			 * \param [in,out]	out	The output.
			 */
			template<typename T, size_t size>
			void ToBinary(std::array<T, size>& out) const
			{
				constexpr size_t totalSize = size * sizeof(T);
				return ToBinary(out.data(), totalSize);
			}

			/**
			 * \brief	Convert this object into a little endian binary
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	out	The output.
			 */
			template<typename T>
			void ToBinary(std::vector<T>& out) const
			{
				return ToBinary(out.data(), out.size() * sizeof(T));
			}

			/**
			* \brief	Converts this big number to a little endian binary
			*
			* \param [in,out]	out 	The reference to the output buffer.
			*/
			template<typename T>
			void ToBinary(T& out, const StructIn&) const
			{
				return ToBinary(&out, sizeof(T));
			}

			/**
			* \brief	Converts this big number to a big endian binary
			*
			* \param [in,out]	out 	If non-null, the output address.
			* \param 		  	size	The size of the output buffer.
			*/
			void ToBinary(void* out, const size_t size, const BigEndian&) const;

			/**
			 * \brief	Convert this object into a big endian binary
			 *
			 * \tparam	T   	Generic type parameter.
			 * \tparam	size	Size of the the array.
			 * \param [in,out]	out		  	The out.
			 * \param 		  	parameter2	Indicate this is converted to big endian.
			 */
			template<typename T, size_t size>
			void ToBinary(std::array<T, size>& out, const BigEndian&) const
			{
				constexpr size_t totalSize = size * sizeof(T);
				return ToBinary(out.data(), totalSize, sk_bigEndian);
			}

			/**
			 * \brief	Convert this object into a big endian binary
			 *
			 * \tparam		T		Generic type parameter.
			 * \param [in,out]	out		  	The output.
			 * \param 		  	parameter2	Indicate this is converted to big endian.
			 */
			template<typename T>
			void ToBinary(std::vector<T>& out, const BigEndian&) const
			{
				return ToBinary(out.data(), out.size() * sizeof(T), sk_bigEndian);
			}

			/**
			* \brief	Converts this big number to a big endian binary
			*
			* \param [in,out]	out 	The reference to the output buffer.
			 * \param 		  	parameter2	Indicate output buffer is a struct.
			 * \param 		  	parameter3	Indicate this is converted to big endian.
			*/
			template<typename T>
			void ToBinary(T& out, const StructIn&, const BigEndian&) const
			{
				return ToBinary(&out, sizeof(T), sk_bigEndian);
			}
		private:

			/**
			 * \brief	Construct a big number by referencing an existing binary data in little-endian.
			 * 			No error checking on size.
			 *
			 * \param	ptr		  	The pointer.
			 * \param	size	  	The size.
			 * \param	parameter3	The third parameter.
			 */
			ConstBigNumber(const void* ptr, const size_t size, const Generate&) noexcept;

			/**
			 * \brief	Converts this object to a big endian hexadecimal string
			 *
			 * \return	This object as a std::string.
			 */
			std::string ToBigEndianHexStr() const;

		};
	}
}