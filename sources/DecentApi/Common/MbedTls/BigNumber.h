#pragma once

#include "ObjBase.h"

#include <cstdint>

#include <string>
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
			 * \exception: MbedTlsObj::MbedTlsException
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
			BigNumber() :
				BigNumber(sk_empty)
			{}

			/**
			* \brief	Constructor that generate a big number. Nothing has been filled-in.
			*
			* \param	parameter1	The dummy variable that indicates the need for generating a big number object.
			*/
			BigNumber(const Empty&);

			/**
			 * \brief	Construct a big number by copy an existing binary data in little-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	ptr		  	The pointer.
			 * \param	size	  	The size.
			 * \param	isPositive	(Optional) True if is positive, false if not.
			 */
			BigNumber(const void* ptr, const size_t size, bool isPositive = true);

			/**
			 * \brief	Constructor that constructs BigNumber from uint64_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	val	The value.
			 */
			BigNumber(uint64_t val) :
				BigNumber(&val, sizeof(val), true)
			{}

			/**
			 * \brief	Constructor that constructs BigNumber from int64_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	val	The value.
			 */
			BigNumber(int64_t val) :
				BigNumber(val >= 0 ? static_cast<uint64_t>(val) : static_cast<uint64_t>(-val))
			{
				if (val < 0)
				{
					FlipSign();
				}
			}

			/**
			 * \brief	Constructor that constructs BigNumber from uint32_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	val	The value.
			 */
			BigNumber(uint32_t val) :
				BigNumber(static_cast<uint64_t>(val))
			{}

			/**
			 * \brief	Constructor that constructs BigNumber from int32_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	val	The value.
			 */
			BigNumber(int32_t val) :
				BigNumber(static_cast<int64_t>(val))
			{}

			/**
			 * \brief	Constructor that constructs BigNumber from uint16_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	val	The value.
			 */
			BigNumber(uint16_t val) :
				BigNumber(static_cast<uint64_t>(val))
			{}

			/**
			 * \brief	Constructor that constructs BigNumber from int16_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	val	The value.
			 */
			BigNumber(int16_t val) :
				BigNumber(static_cast<int64_t>(val))
			{}

			/**
			 * \brief	Constructor that constructs BigNumber from uint8_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	val	The value.
			 */
			BigNumber(uint8_t val) :
				BigNumber(static_cast<uint64_t>(val))
			{}

			/**
			 * \brief	Constructor that constructs BigNumber from int8_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	val	The value.
			 */
			BigNumber(int8_t val) :
				BigNumber(static_cast<int64_t>(val))
			{}

			/**
			 * \brief	Constructor that constructs BigNumber from char.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	val	The value.
			 */
			BigNumber(char val) :
				BigNumber(static_cast<int64_t>(val))
			{}

			/**
			 * \brief	Construct a big number by copying an existing binary data in little-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \tparam	ArrayT	Type of the array t.
			 * \param	arr		  	The array.
			 * \param	isPositive	True if is positive, false if not.
			 */
			template<typename ArrayT>
			BigNumber(const ArrayT& arr, bool isPositive) :
				BigNumber(detail::GetPtr(arr), detail::GetSize(arr), isPositive)
			{}

			/**
			 * \brief	Construct a big number by copying an existing binary data in little-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	in		  	The input.
			 * \param	parameter2	Indicate the input is a struct.
			 */
			template<typename T>
			BigNumber(const T& in, bool isPositive, const StructIn&) :
				BigNumber(&in, sizeof(T), isPositive)
			{}

			/**
			 * \brief	Construct a big number by copying an existing binary data in big-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \param	ptr		  	The pointer.
			 * \param	size	  	The size.
			 * \param	parameter3	Indicate the input is in big endian.
			 * \param	isPositive	(Optional) True if is positive, false if not.
			 */
			BigNumber(const void* ptr, const size_t size, const BigEndian&, bool isPositive = true);

			/**
			 * \brief	Construct a big number by copying an existing binary data in big-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \tparam	ArrayT	Type of the array t.
			 * \param	in		  	The input.
			 * \param	isPositive	True if is positive, false if not.
			 * \param	parameter3	Indicate the input is in big endian.
			 */
			template<typename ArrayT>
			BigNumber(const ArrayT& arr, bool isPositive, const BigEndian&) :
				BigNumber(detail::GetPtr(arr), detail::GetSize(arr), sk_bigEndian, isPositive)
			{}

			/**
			 * \brief	Construct a big number by copying an existing binary data in big-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error happened.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	in		  	The input.
			 * \param	parameter2	Indicate the input is a struct.
			 * \param	parameter3	Indicate the input is in big endian.
			 */
			template<typename T>
			BigNumber(const T& in, bool isPositive, const StructIn&, const BigEndian&) :
				BigNumber(&in, sizeof(T), sk_bigEndian, isPositive)
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
			 * \brief	Construct a big number by copying an existing mbed TLS big number.
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 */
			BigNumber(const mbedtls_mpi& rhs);

			/**
			 * \brief	Copy constructor
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 */
			BigNumber(const BigNumber& rhs);

			/**
			 * \brief	Constructor a big number by copying an existing const big number.
			 *
			 * \exception: MbedTlsObj::MbedTlsException
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

			/**
			 * \brief	Assignment operator (deep copy).
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			BigNumber& operator=(const BigNumber& rhs);

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			BigNumber& operator=(BigNumber&& rhs) noexcept
			{
				ObjBase::operator=(std::forward<ObjBase>(rhs));
				return *this;
			}

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
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator+(const BigNumber& rhs) const;

			/**
			 * \brief	Addition operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator+(int64_t rhs) const;
			BigNumber operator+(int32_t rhs) const { return this->operator+(static_cast<int64_t>(rhs)); }
			BigNumber operator+(int16_t rhs) const { return this->operator+(static_cast<int64_t>(rhs)); }
			BigNumber operator+(int8_t rhs) const { return this->operator+(static_cast<int64_t>(rhs)); }
			BigNumber operator+(uint32_t rhs) const { return this->operator+(static_cast<int64_t>(rhs)); }
			BigNumber operator+(uint16_t rhs) const { return this->operator+(static_cast<int64_t>(rhs)); }
			BigNumber operator+(uint8_t rhs) const { return this->operator+(static_cast<int64_t>(rhs)); }

			/**
			 * \brief	Subtraction operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator-(const BigNumber& rhs) const;

			/**
			 * \brief	Subtraction operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator-(int64_t rhs) const;
			BigNumber operator-(int32_t rhs) const { return this->operator-(static_cast<int64_t>(rhs)); }
			BigNumber operator-(int16_t rhs) const { return this->operator-(static_cast<int64_t>(rhs)); }
			BigNumber operator-(int8_t rhs) const { return this->operator-(static_cast<int64_t>(rhs)); }
			BigNumber operator-(uint32_t rhs) const { return this->operator-(static_cast<int64_t>(rhs)); }
			BigNumber operator-(uint16_t rhs) const { return this->operator-(static_cast<int64_t>(rhs)); }
			BigNumber operator-(uint8_t rhs) const { return this->operator-(static_cast<int64_t>(rhs)); }

			/**
			 * \brief	Multiplication operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator*(const BigNumber& rhs) const;

			/**
			 * \brief	Multiplication operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator*(uint64_t rhs) const;
			BigNumber operator*(uint32_t rhs) const { return this->operator*(static_cast<uint64_t>(rhs)); }
			BigNumber operator*(uint16_t rhs) const { return this->operator*(static_cast<uint64_t>(rhs)); }
			BigNumber operator*(uint8_t rhs) const { return this->operator*(static_cast<uint64_t>(rhs)); }

			/**
			 * \brief	Division operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator/(const BigNumber& rhs) const;

			/**
			 * \brief	Division operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator/(int64_t rhs) const;
			BigNumber operator/(int32_t rhs) const { return this->operator/(static_cast<int64_t>(rhs)); }
			BigNumber operator/(int16_t rhs) const { return this->operator/(static_cast<int64_t>(rhs)); }
			BigNumber operator/(int8_t rhs) const { return this->operator/(static_cast<int64_t>(rhs)); }
			BigNumber operator/(uint32_t rhs) const { return this->operator/(static_cast<int64_t>(rhs)); }
			BigNumber operator/(uint16_t rhs) const { return this->operator/(static_cast<int64_t>(rhs)); }
			BigNumber operator/(uint8_t rhs) const { return this->operator/(static_cast<int64_t>(rhs)); }

			/**
			 * \brief	Modulus operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator%(const BigNumber& rhs) const;

			/**
			 * \brief	Modulus operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			uint64_t operator%(int64_t rhs) const;
			uint32_t operator%(int32_t rhs) const { return static_cast<uint32_t>(this->operator%(static_cast<int64_t>(rhs))); }
			uint16_t operator%(int16_t rhs) const { return static_cast<uint16_t>(this->operator%(static_cast<int64_t>(rhs))); }
			uint8_t operator%(int8_t rhs) const { return static_cast<uint8_t>(this->operator%(static_cast<int64_t>(rhs))); }
			uint32_t operator%(uint32_t rhs) const { return static_cast<uint32_t>(this->operator%(static_cast<int64_t>(rhs))); }
			uint16_t operator%(uint16_t rhs) const { return static_cast<uint16_t>(this->operator%(static_cast<int64_t>(rhs))); }
			uint8_t operator%(uint8_t rhs) const { return static_cast<uint8_t>(this->operator%(static_cast<int64_t>(rhs))); }

			/**
			 * \brief	Negation operator
			 *
			 * \return	The result of the operation.
			 */
			BigNumber operator-() const;

			/**
			 * \brief	Bitwise left shift operator
			 *
			 * \param	count	Number of bits to shift.
			 *
			 * \return	The shifted result.
			 */
			BigNumber operator<<(size_t count) const;

			/**
			 * \brief	Bitwise right shift operator
			 *
			 * \param	count	Number of bits to shift.
			 *
			 * \return	The shifted result.
			 */
			BigNumber operator>>(size_t count) const;

			/**
			* \brief	Equal comparison operator
			*
			* \param	rhs	The right hand side.
			*
			* \return	True if the first parameter is equal to the second.
			*/
			bool operator==(const BigNumber& rhs) const;

			/**
			 * \brief	Inequality operator
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the parameters are not considered equivalent.
			 */
			bool operator!=(const BigNumber& rhs) const;

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
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator+=(const BigNumber& rhs);

			/**
			 * \brief	Addition assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator+=(int64_t rhs);
			BigNumber& operator+=(int32_t rhs) { return this->operator+=(static_cast<int64_t>(rhs)); }
			BigNumber& operator+=(int16_t rhs) { return this->operator+=(static_cast<int64_t>(rhs)); }
			BigNumber& operator+=(int8_t rhs) { return this->operator+=(static_cast<int64_t>(rhs)); }
			BigNumber& operator+=(uint32_t rhs) { return this->operator+=(static_cast<int64_t>(rhs)); }
			BigNumber& operator+=(uint16_t rhs) { return this->operator+=(static_cast<int64_t>(rhs)); }
			BigNumber& operator+=(uint8_t rhs) { return this->operator+=(static_cast<int64_t>(rhs)); }

			/**
			 * \brief	Subtraction assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator-=(const BigNumber& rhs);

			/**
			 * \brief	Subtraction assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator-=(int64_t rhs);
			BigNumber& operator-=(int32_t rhs) { return this->operator-=(static_cast<int64_t>(rhs)); }
			BigNumber& operator-=(int16_t rhs) { return this->operator-=(static_cast<int64_t>(rhs)); }
			BigNumber& operator-=(int8_t rhs) { return this->operator-=(static_cast<int64_t>(rhs)); }
			BigNumber& operator-=(uint32_t rhs) { return this->operator-=(static_cast<int64_t>(rhs)); }
			BigNumber& operator-=(uint16_t rhs) { return this->operator-=(static_cast<int64_t>(rhs)); }
			BigNumber& operator-=(uint8_t rhs) { return this->operator-=(static_cast<int64_t>(rhs)); }

			/**
			 * \brief	Multiplication assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator*=(const BigNumber& rhs);

			/**
			 * \brief	Multiplication assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator*=(uint64_t rhs);
			BigNumber& operator*=(uint32_t rhs) { return this->operator*=(static_cast<uint64_t>(rhs)); }
			BigNumber& operator*=(uint16_t rhs) { return this->operator*=(static_cast<uint64_t>(rhs)); }
			BigNumber& operator*=(uint8_t rhs) { return this->operator*=(static_cast<uint64_t>(rhs)); }

			/**
			 * \brief	Division assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator/=(const BigNumber& rhs);

			/**
			 * \brief	Division assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator/=(int64_t rhs);
			BigNumber& operator/=(int32_t rhs) { return this->operator/=(static_cast<int64_t>(rhs)); }
			BigNumber& operator/=(int16_t rhs) { return this->operator/=(static_cast<int64_t>(rhs)); }
			BigNumber& operator/=(int8_t rhs) { return this->operator/=(static_cast<int64_t>(rhs)); }
			BigNumber& operator/=(uint32_t rhs) { return this->operator/=(static_cast<int64_t>(rhs)); }
			BigNumber& operator/=(uint16_t rhs) { return this->operator/=(static_cast<int64_t>(rhs)); }
			BigNumber& operator/=(uint8_t rhs) { return this->operator/=(static_cast<int64_t>(rhs)); }

			/**
			 * \brief	Modulus assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator%=(const BigNumber& rhs);

			/**
			 * \brief	Modulus assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator%=(int64_t rhs);
			BigNumber& operator%=(int32_t rhs) { return this->operator%=(static_cast<int64_t>(rhs)); }
			BigNumber& operator%=(int16_t rhs) { return this->operator%=(static_cast<int64_t>(rhs)); }
			BigNumber& operator%=(int8_t rhs) { return this->operator%=(static_cast<int64_t>(rhs)); }
			BigNumber& operator%=(uint32_t rhs) { return this->operator%=(static_cast<int64_t>(rhs)); }
			BigNumber& operator%=(uint16_t rhs) { return this->operator%=(static_cast<int64_t>(rhs)); }
			BigNumber& operator%=(uint8_t rhs) { return this->operator%=(static_cast<int64_t>(rhs)); }

			/**
			 * \brief	Bitwise left shift assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	count	Number of.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator<<=(size_t count);

			/**
			 * \brief	Bitwise right shift assignment operator
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	count	Number of.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator>>=(size_t count);

			/**
			 * \brief	Converts this big number to a little endian binary
			 * 
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param [in,out]	out 	If non-null, the output address.
			 * \param 		  	size	The size of the output buffer.
			 */
			void ToBinary(void* out, const size_t size) const;

			/**
			 * \brief	Convert this object into a binary representation
			 *
			 * \exception: MbedTlsObj::MbedTlsException
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
			 * \exception: MbedTlsObj::MbedTlsException
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
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	out		  	The reference to the output space.
			 * \param 		  	parameter2	Indicate the output is in a struct.
			 */
			template<typename T>
			void ToBinary(T& out, const StructIn&) const
			{
				return ToBinary(&out, sizeof(T));
			}

			/**
			 * \brief	Converts this big number to a big endian binary
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param [in,out]	out		  	If non-null, the output address.
			 * \param 		  	size	  	The size of the output buffer.
			 * \param 		  	parameter3	Indicate the output should be in big endian.
			 */
			void ToBinary(void* out, const size_t size, const BigEndian&) const;

			/**
			 * \brief	Convert this object into a binary representation
			 *
			 * \exception: MbedTlsObj::MbedTlsException
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
			 * \exception: MbedTlsObj::MbedTlsException
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
			 * \exception: MbedTlsObj::MbedTlsException
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

			/**
			 * \brief	Query if this big number is positive
			 *
			 * \return	True if positive, false if not.
			 */
			bool IsPositive() const;

			/**
			 * \brief	Flip sign (i.e. negative to positive, or positive to negative.)
			 *
			 * \return	A reference to a this instance.
			 */
			BigNumber& FlipSign();

			/**
			 * \brief	Sets a bit
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	pos	The position; start from zero.
			 * \param	bit	True for 1; false for 0.
			 *
			 * \return	A reference to this instance.
			 */
			BigNumber& SetBit(const size_t pos, bool bit);

			/**
			 * \brief	Gets a bit
			 *
			 * \param	pos	The position; start from zero.
			 *
			 * \return	Got bit, true for 1 and false for 0.
			 */
			bool GetBit(const size_t pos);

		private:
			BigNumber(mbedtls_mpi* ptr, FreeFuncType freeFunc) noexcept :
				ObjBase(ptr, freeFunc)
			{}

			friend class ConstBigNumber;
		};

		class ConstBigNumber
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
				static_assert(!((size * sizeof(T)) % sizeof(mbedtls_mpi_uint)), "The size of the given big number must be a factor of 8-Byte (64-bit). ");
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
				m_bigNum(std::forward<BigNumber>(other.m_bigNum))
			{}

			ConstBigNumber(const ConstBigNumber& rhs) = delete;

			/** \brief	Destructor */
			virtual ~ConstBigNumber() noexcept {}

			/**
			 * \brief	Cast to a reference to a const BigNumber.
			 *
			 * \return	A reference to a const BigNumber.
			 */
			operator const BigNumber&() const noexcept;

			/**
			 * \brief	Get a reference to a const BigNumber.
			 *
			 * \return	A reference to a const BigNumber.
			 */
			const BigNumber& Get() const noexcept;

			/**
			 * \brief	Swaps the given right hand side var
			 *
			 * \param	rhs	The right hand side.
			 */
			void Swap(ConstBigNumber& rhs) noexcept
			{
				m_bigNum.Swap(rhs.m_bigNum);
			}

			//Overriding the const operators:

			BigNumber operator+(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) + rhs; }
			BigNumber operator+(int64_t rhs) const { return static_cast<const BigNumber&>(*this) + rhs; }
			BigNumber operator-(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) - rhs; }
			BigNumber operator-(int64_t rhs) const { return static_cast<const BigNumber&>(*this) - rhs; }
			BigNumber operator*(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) * rhs; }
			BigNumber operator*(uint64_t rhs) const { return static_cast<const BigNumber&>(*this) * rhs; }
			BigNumber operator/(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) / rhs; }
			BigNumber operator/(int64_t rhs) const { return static_cast<const BigNumber&>(*this) / rhs; }
			BigNumber operator%(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) % rhs; }
			uint64_t operator%(int64_t rhs) const { return static_cast<const BigNumber&>(*this) % rhs; }
			BigNumber operator-() const { return -static_cast<const BigNumber&>(*this); }

			bool operator==(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) == rhs; }
			bool operator!=(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) != rhs; }
			bool operator<(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) < rhs; }
			bool operator<=(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) <= rhs; }
			bool operator>(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) > rhs; }
			bool operator>=(const BigNumber& rhs) const { return static_cast<const BigNumber&>(*this) >= rhs; }

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

			BigNumber m_bigNum;

		};
	}
}