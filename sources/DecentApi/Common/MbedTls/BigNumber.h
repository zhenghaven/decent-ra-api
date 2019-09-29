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

		class BigNumberBase : public ObjBase<mbedtls_mpi>
		{
		public: //static members:

			/**
			 * \brief	Function that frees MbedTLS object and delete the pointer.
			 *
			 * \param [in,out]	ptr	If non-null, the pointer.
			 */
			static void FreeObject(mbedtls_mpi* ptr);

			/**
			 * \brief	Bytes to big endian hexadecimal string
			 *
			 * \param	ptr 	The pointer to the bytes in memory.
			 * \param	size	The size of the bytes.
			 *
			 * \return	A std::string.
			 */
			static std::string BytesToBigEndianHexStr(const void * ptr, const size_t size);

		public:

			/** \brief	Default constructor. Construct a non-null, initialized, but empty big number. */
			BigNumberBase();

			/**
			 * \brief	Copy constructor. Make a deep copy (by using mbedtls_mpi_copy) of a mbedTLS MPI
			 * 			object. But, if rhs is null, then copy will be null as well.
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 *
			 * \param	rhs	The right hand side.
			 */
			BigNumberBase(const BigNumberBase& rhs);

			/**
			 * \brief	Move constructor. Move the mbedTLS MPI object to this new instance. The MPI object
			 * 			originally held by this instance will be emptied.
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			BigNumberBase(BigNumberBase&& rhs);

			/**
			 * \brief	Make a deep copy (by using mbedtls_mpi_copy) of a mbedTLS MPI object.
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 *
			 * \param	rhs	The right hand side.
			 */
			BigNumberBase(const mbedtls_mpi& rhs);

			/** \brief	Destructor */
			virtual ~BigNumberBase();

			/**
			 * \brief	Assignment operator. Make a deep copy (by using mbedtls_mpi_copy) of a mbedTLS MPI
			 * 			object to this instance. But, if rhs is null, then this instance will become null as
			 * 			well.
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			BigNumberBase& operator=(const BigNumberBase& rhs);

			/**
			 * \brief	Move assignment operator. Note: object held by this instance will be free first, and
			 * 			then the held object from RHS will be moved into this instance.
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			BigNumberBase& operator=(BigNumberBase&& rhs);

			using ObjBase::Swap;

			/**
			 * \brief	Query if this big number is positive
			 *
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \return	True if positive, false if not.
			 */
			bool IsPositive() const;

			/**
			 * \brief	Gets the size of this big number in Bytes.
			 *
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \return	The size.
			 */
			size_t GetSize() const;

			/**
			 * \brief	Gets the size of this big number in bits.
			 *
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \return	The size.
			 */
			size_t GetBitSize() const;

			/**
			 * \brief	Gets a bit
			 *
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \param	pos	The position; start from zero.
			 *
			 * \return	Got bit, true for 1 and false for 0.
			 */
			bool GetBit(const size_t pos) const;

			/**
			 * \brief	Convert this object into a binary representation
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \tparam	ContainerType	Type of the container.
			 * \param [in,out]	out	The output.
			 */
			template<typename ContainerType>
			void ToBinary(ContainerType& out) const
			{
				return ToBinary(detail::GetPtr(out), detail::GetSize(out));
			}

			/**
			 * \brief	Converts this big number to a little endian binary
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \tparam	StructType	Type of the struct (any C primitive type).
			 * \param [in,out]	out	The reference to the output space.
			 */
			template<typename StructType>
			void ToBinaryStruct(StructType& out) const
			{
				return ToBinary(&out, sizeof(StructType));
			}

			/**
			 * \brief	Convert this object into a binary representation
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \tparam	ContainerType	Type of the container.
			 * \param [in,out]	out	The output.
			 */
			template<typename ContainerType>
			void ToBigEndianBinary(ContainerType& out) const
			{
				return ToBigEndianBinary(detail::GetPtr(out), detail::GetSize(out));
			}

			/**
			 * \brief	Converts this big number to a big endian binary
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param [in,out]	out		  	The reference to the output buffer.
			 * \param 		  	parameter2	Indicate the output buffer is a struct.
			 * \param 		  	parameter3	Indicate the output should be in big endian.
			 */
			template<typename StructType>
			void ToBigEndianBinaryStruct(StructType& out) const
			{
				return ToBigEndianBinary(&out, sizeof(StructType));
			}

			/**
			 * \brief	Converts this object to a big endian hexadecimal string
			 *
			 * \return	This object as a std::string.
			 */
			std::string ToBigEndianHexStr() const;

			/**
			 * \brief	Compares this const BigNumber&amp; object to another to determine their relative
			 * 			ordering.
			 *
			 * \exception	RuntimeException	Thrown when this instance or the given RHS is null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	Negative if 'rhs' is less than this instance, 0 if they are equal, or positive if it
			 * 			is greater.
			 */
			int Compare(const BigNumberBase& rhs) const;

			/**
			 * \brief	Equal comparison operator.
			 *
			 * \exception	RuntimeException	Thrown when this instance or the given RHS is null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is equal to the second.
			 */
			bool operator==(const BigNumberBase& rhs) const;

			/**
			 * \brief	Inequality operator.
			 *
			 * \exception	RuntimeException	Thrown when this instance or the given RHS is null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the parameters are not considered equivalent.
			 */
			bool operator!=(const BigNumberBase& rhs) const;

			/**
			 * \brief	Less-than comparison operator.
			 *
			 * \exception	RuntimeException	Thrown when this instance or the given RHS is null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is less than the second.
			 */
			bool operator<(const BigNumberBase& rhs) const;

			/**
			 * \brief	Less-than-or-equal comparison operator.
			 *
			 * \exception	RuntimeException	Thrown when this instance or the given RHS is null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is less than or equal to the second.
			 */
			bool operator<=(const BigNumberBase& rhs) const;

			/**
			 * \brief	Greater-than comparison operator.
			 *
			 * \exception	RuntimeException	Thrown when this instance or the given RHS is null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is greater than to the second.
			 */
			bool operator>(const BigNumberBase& rhs) const;

			/**
			 * \brief	Greater-than-or-equal comparison operator.
			 *
			 * \exception	RuntimeException	Thrown when this instance or the given RHS is null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	True if the first parameter is greater than or equal to the second.
			 */
			bool operator>=(const BigNumberBase& rhs) const;

			/**
			 * \brief	Modulus operator
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
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

		protected:

			/**
			 * \brief	Constructor with more flexibility. Only pass pointer and free function to the ObjBase;
			 * 			no other instructions after that.
			 *
			 * \param [in,out]	ptr			The pointer to the mbedTLS MPI object.
			 * \param 		  	freeFunc	The free function used to free the mbedTLS MPI object.
			 */
			BigNumberBase(mbedtls_mpi* ptr, FreeFuncType freeFunc);

			/**
			 * \brief	Converts this big number to a little endian binary
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \param [in,out]	out 	If non-null, the output buffer.
			 * \param 		  	size	The size of the output buffer.
			 */
			void ToBinary(void* out, const size_t size) const;

			/**
			 * \brief	Converts this big number to a big endian binary
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 * \exception	RuntimeException	Thrown when calling this method while this instance is in
			 * 									null state.
			 *
			 * \param [in,out]	out 	If non-null, the output buffer.
			 * \param 		  	size	The size of the output buffer.
			 */
			void ToBigEndianBinary(void* out, const size_t size) const;

		};

		class ConstBigNumber : public BigNumberBase
		{
		public: // static members:
			static void FreeDummyMpi(mbedtls_mpi* ptr);

		public:
			ConstBigNumber() = delete;

			/**
			 * \brief	Constructor that accept a reference to mbedtls_mpi object, thus, this instance
			 * 			doesn't has the ownership.
			 *
			 * \param [in,out]	ref	The reference.
			 */
			ConstBigNumber(mbedtls_mpi& ref);

			/**
			 * \brief	Construct a big number by referencing an existing binary data in little-endian. NOTE:
			 * 			REFERENCE ONLY, there is no copy operation, so make sure the referenced data's life
			 * 			time!
			 *
			 * \tparam	ArrayType	Generic type parameter.
			 * \tparam	size	 	Size of the array.
			 * \param	in	The input.
			 */
			template<typename ArrayType, size_t size>
			ConstBigNumber(const ArrayType(&in)[size]) :
				ConstBigNumber(detail::GetPtr(in), detail::GetSize(in), sk_gen)
			{
				static_assert((detail::ContainerPrpt<detail::remove_cvref<decltype(in)>::type>::sk_ctnSize % sizeof(mbedtls_mpi_uint)) == 0,
					"The size of the given big number must be a factor of 8-Byte (64-bit).");
			}

			/**
			 * \brief	Construct a big number by referencing an existing binary data in little-endian.
			 * 			NOTE: REFERENCE ONLY, there is no copy operation, so make sure the referenced data's life time!
			 *
			 * \tparam	T   	Generic type parameter.
			 * \tparam	size	Size of the array.
			 * \param	in	The input.
			 */
			template<typename T, size_t size>
			ConstBigNumber(const std::array<T, size>& in) :
				ConstBigNumber(detail::GetPtr(in), detail::GetSize(in), sk_gen)
			{
				static_assert((detail::ContainerPrpt<detail::remove_cvref<decltype(in)>::type>::sk_ctnSize % sizeof(mbedtls_mpi_uint)) == 0,
					"The size of the given big number must be a factor of 8-Byte (64-bit).");
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
				ConstBigNumber(detail::GetPtr(in), detail::GetSize(in))
			{}

			ConstBigNumber(const ConstBigNumber& rhs) = delete;

			/**
			 * \brief	Move constructor
			 *
			 * \param	rhs	The right hand side.
			 */
			ConstBigNumber(ConstBigNumber&& rhs);

			/** \brief	Destructor */
			virtual ~ConstBigNumber();

			using BigNumberBase::Swap;

			const mbedtls_mpi* GetConst() const noexcept;

			ConstBigNumber& operator=(const ConstBigNumber& rhs) = delete;

			/**
			 * \brief	Move assignment operator.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			ConstBigNumber& operator=(ConstBigNumber&& rhs);

		protected:

			/**
			 * \brief	Construct a big number by referencing an existing binary data in little-endian. NOTE:
			 * 			REFERENCE ONLY, there is no copy operation, so make sure the referenced data's life
			 * 			time!
			 *
			 * \param	ptr 	The pointer.
			 * \param	size	The size.
			 */
			ConstBigNumber(const void* ptr, const size_t size);

			/**
			 * \brief	Construct a big number by referencing an existing binary data in little-endian.
			 * 			No error checking on size.
			 *
			 * \param	ptr		  	The pointer.
			 * \param	size	  	The size.
			 * \param	parameter3	The third parameter.
			 */
			ConstBigNumber(const void* ptr, const size_t size, const Generate&);

			using BigNumberBase::Get;

		};

		class BigNumber : public BigNumberBase
		{
		public: //static members:

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

		public:

			/** \brief	Default constructor. Construct a non-null, initialized, but empty big number. */
			BigNumber();

			/**
			 * \brief	Move constructor. Move the mbedTLS MPI object of RHS to this new instance. The MPI
			 * 			object originally held by this instance will be emptied.
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			BigNumber(BigNumber&& rhs);

			/**
			 * \brief	Copy constructor. Make a deep copy (by using mbedtls_mpi_copy) of a mbedTLS MPI
			 * 			object. But, if rhs is null, then copy will be null as well.
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 *
			 * \param	rhs	The right hand side.
			 */
			BigNumber(const BigNumber& rhs) :
				BigNumber(static_cast<const BigNumberBase&>(rhs))
			{}

			/**
			 * \brief	Copy constructor. Make a deep copy (by using mbedtls_mpi_copy) of a mbedTLS MPI
			 * 			object. But, if rhs is null, then copy will be null as well.
			 *
			 * \exception	MbedTlsException	Error return by mbedTLS C function calls.
			 *
			 * \param	rhs	The right hand side.
			 */
			BigNumber(const BigNumberBase& rhs);

			/**
			 * \brief	Constructor that constructs BigNumber from uint64_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 *
			 * \param	isPositive	True if is positive, false if not.
			 * \param	val		  	The value.
			 */
			BigNumber(bool isPositive, uint64_t val) :
				BigNumber(&val, sizeof(val), isPositive)
			{}

			/**
			 * \brief	Constructor that constructs BigNumber from uint64_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 *
			 * \param	val	The value.
			 */
			BigNumber(uint64_t val) :
				BigNumber(&val, sizeof(val), true)
			{}

			BigNumber(uint32_t val) : BigNumber(static_cast<uint64_t>(val)) {}
			BigNumber(uint16_t val) : BigNumber(static_cast<uint64_t>(val)) {}
			BigNumber(uint8_t val) : BigNumber(static_cast<uint64_t>(val)) {}

			/**
			 * \brief	Constructor that constructs BigNumber from int64_t.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 *
			 * \param	val	The value.
			 */
			BigNumber(int64_t val) :
				BigNumber(val >= 0, val >= 0 ? static_cast<uint64_t>(val) : static_cast<uint64_t>(-val))
			{}

			BigNumber(int32_t val) : BigNumber(static_cast<int64_t>(val)) {}
			BigNumber(int16_t val) : BigNumber(static_cast<int64_t>(val)) {}
			BigNumber(int8_t val) : BigNumber(static_cast<int64_t>(val)) {}
			BigNumber(char val) : BigNumber(static_cast<int64_t>(val)) {}

			/**
			 * \brief	Construct a big number by copying an existing binary data in little-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 *
			 * \tparam	ContainerType	Type of the container.
			 * \param	arr		  	The array.
			 * \param	isPositive	True if is positive, false if not.
			 */
			template<typename ContainerType>
			BigNumber(const ContainerType& arr, bool isPositive) :
				BigNumber(detail::GetPtr(arr), detail::GetSize(arr), isPositive)
			{}

			/**
			 * \brief	Construct a big number by copying an existing binary data in little-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 *
			 * \tparam	StructType	Type of the struct.
			 * \param	parameter1	Indicate the input is a struct.
			 * \param	in		  	The input.
			 * \param	isPositive	True if is positive, false if not.
			 */
			template<typename StructType>
			BigNumber(const StructIn&, const StructType& in, bool isPositive) :
				BigNumber(&in, sizeof(StructType), isPositive)
			{}

			/**
			 * \brief	Construct a big number by copying an existing binary data in big-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 *
			 * \tparam	ContainerType	Type of the container.
			 * \param	parameter1	Indicate the input is in big endian.
			 * \param	arr		  	The array.
			 * \param	isPositive	True if is positive, false if not.
			 */
			template<typename ContainerType>
			BigNumber(const BigEndian&, const ContainerType& arr, bool isPositive) :
				BigNumber(detail::GetPtr(arr), detail::GetSize(arr), sk_bigEndian, isPositive)
			{}

			/**
			 * \brief	Construct a big number by copying an existing binary data in big-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 *
			 * \tparam	T	Generic type parameter.
			 * \param	in		  	The input.
			 * \param	parameter2	Indicate the input is a struct.
			 * \param	parameter3	Indicate the input is in big endian.
			 */
			template<typename T>
			BigNumber(const BigEndian&, const StructIn&, const T& in, bool isPositive) :
				BigNumber(&in, sizeof(T), sk_bigEndian, isPositive)
			{}

			/** \brief	Destructor */
			virtual ~BigNumber();

		protected: // Protected constructers:

			/**
			 * \brief	Construct a big number by copy an existing binary data in little-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 *
			 * \param	ptr		  	The pointer.
			 * \param	size	  	The size.
			 * \param	isPositive	(Optional) True if is positive, false if not.
			 */
			BigNumber(const void* ptr, const size_t size, bool isPositive);

			/**
			 * \brief	Construct a big number by copying an existing binary data in big-endian.
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 *
			 * \param	parameter1	Indicate the input is in big endian.
			 * \param	ptr		  	The pointer.
			 * \param	size	  	The size.
			 * \param	isPositive	True if is positive, false if not.
			 */
			BigNumber(const BigEndian&, const void* ptr, const size_t size, bool isPositive);
			
		public:

			using BigNumberBase::Swap;

			/**
			 * \brief	Assignment operator (deep copy).
			 *
			 * \exception: MbedTlsObj::MbedTlsException
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			BigNumber& operator=(const BigNumberBase& rhs);

			/**
			 * \brief	Move assignment operator
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this instance.
			 */
			BigNumber& operator=(BigNumber&& rhs);

			/**
			 * \brief	Addition assignment operator
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance or RHS is in null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator+=(const BigNumberBase& rhs);

			/**
			 * \brief	Addition assignment operator
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance is in null state.
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
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance or RHS is in null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator-=(const BigNumberBase& rhs);

			/**
			 * \brief	Subtraction assignment operator
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance is in null state.
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
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance or RHS is in null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator*=(const BigNumberBase& rhs);

			/**
			 * \brief	Multiplication assignment operator
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance is in null state.
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
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance or RHS is in null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator/=(const BigNumberBase& rhs);

			/**
			 * \brief	Division assignment operator
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance is in null state.
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
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance or RHS is in null state.
			 *
			 * \param	rhs	The right hand side.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator%=(const BigNumberBase& rhs);

			/**
			 * \brief	Modulus assignment operator
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance is in null state.
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
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance is in null state.
			 *
			 * \param	count	Number of.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator<<=(uint64_t rhs);
			BigNumber& operator<<=(uint32_t rhs) { return this->operator<<=(static_cast<uint64_t>(rhs)); }
			BigNumber& operator<<=(uint16_t rhs) { return this->operator<<=(static_cast<uint64_t>(rhs)); }
			BigNumber& operator<<=(uint8_t  rhs) { return this->operator<<=(static_cast<uint64_t>(rhs)); }

			/**
			 * \brief	Bitwise right shift assignment operator
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance is in null state.
			 *
			 * \param	count	Number of.
			 *
			 * \return	The result of the operation.
			 */
			BigNumber& operator>>=(uint64_t count);
			BigNumber& operator>>=(uint32_t rhs) { return this->operator>>=(static_cast<uint64_t>(rhs)); }
			BigNumber& operator>>=(uint16_t rhs) { return this->operator>>=(static_cast<uint64_t>(rhs)); }
			BigNumber& operator>>=(uint8_t  rhs) { return this->operator>>=(static_cast<uint64_t>(rhs)); }

			/**
			 * \brief	Flip sign (i.e. negative to positive, or positive to negative.)
			 *
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance is in null state.
			 *
			 * \return	A reference to a this instance.
			 */
			BigNumber& FlipSign();

			/**
			 * \brief	Sets a bit
			 *
			 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
			 * \exception	MbedTlsObj::RuntimeException	Thrown when this instance is in null state.
			 *
			 * \param	pos	The position; start from zero.
			 * \param	bit	True for 1; false for 0.
			 *
			 * \return	A reference to this instance.
			 */
			BigNumber& SetBit(const size_t pos, bool bit);

		};

		/**
		 * \brief	Negation operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 * \exception	RuntimeException				Thrown when the given BigNumberBase object is in
		 * 												null state.
		 *
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator-(const BigNumberBase& rhs);

		/**
		 * \brief	Addition operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 *
		 * \param	lhs	The first value.
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator+(const BigNumberBase& lhs, const BigNumberBase& rhs);

		/**
		 * \brief	Addition operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 *
		 * \param	lhs	The first value.
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator+(const BigNumberBase& lhs, int64_t  rhs);
		inline BigNumber operator+(const BigNumberBase& lhs, int32_t  rhs) { return lhs + static_cast<int64_t>(rhs); }
		inline BigNumber operator+(const BigNumberBase& lhs, int16_t  rhs) { return lhs + static_cast<int64_t>(rhs); }
		inline BigNumber operator+(const BigNumberBase& lhs, int8_t   rhs) { return lhs + static_cast<int64_t>(rhs); }
		inline BigNumber operator+(const BigNumberBase& lhs, uint32_t rhs) { return lhs + static_cast<int64_t>(rhs); }
		inline BigNumber operator+(const BigNumberBase& lhs, uint16_t rhs) { return lhs + static_cast<int64_t>(rhs); }
		inline BigNumber operator+(const BigNumberBase& lhs, uint8_t  rhs) { return lhs + static_cast<int64_t>(rhs); }
		inline BigNumber operator+(int64_t  lhs, const BigNumberBase& rhs) { return rhs + lhs; }
		inline BigNumber operator+(int32_t  lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) + rhs; }
		inline BigNumber operator+(int16_t  lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) + rhs; }
		inline BigNumber operator+(int8_t   lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) + rhs; }
		inline BigNumber operator+(uint32_t lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) + rhs; }
		inline BigNumber operator+(uint16_t lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) + rhs; }
		inline BigNumber operator+(uint8_t  lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) + rhs; }

		/**
		 * \brief	Subtraction operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 *
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator-(const BigNumberBase& lhs, const BigNumberBase& rhs);

		/**
		 * \brief	Subtraction operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 *
		 * \param	lhs	The first value.
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator-(const BigNumberBase& lhs, int64_t  rhs);
		inline BigNumber operator-(const BigNumberBase& lhs, int32_t  rhs) { return lhs - static_cast<int64_t>(rhs); }
		inline BigNumber operator-(const BigNumberBase& lhs, int16_t  rhs) { return lhs - static_cast<int64_t>(rhs); }
		inline BigNumber operator-(const BigNumberBase& lhs, int8_t   rhs) { return lhs - static_cast<int64_t>(rhs); }
		inline BigNumber operator-(const BigNumberBase& lhs, uint32_t rhs) { return lhs - static_cast<int64_t>(rhs); }
		inline BigNumber operator-(const BigNumberBase& lhs, uint16_t rhs) { return lhs - static_cast<int64_t>(rhs); }
		inline BigNumber operator-(const BigNumberBase& lhs, uint8_t  rhs) { return lhs - static_cast<int64_t>(rhs); }
		inline BigNumber operator-(int64_t  lhs, const BigNumberBase& rhs) { return lhs + (-rhs); }
		inline BigNumber operator-(int32_t  lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) - rhs; }
		inline BigNumber operator-(int16_t  lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) - rhs; }
		inline BigNumber operator-(int8_t   lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) - rhs; }
		inline BigNumber operator-(uint32_t lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) - rhs; }
		inline BigNumber operator-(uint16_t lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) - rhs; }
		inline BigNumber operator-(uint8_t  lhs, const BigNumberBase& rhs) { return static_cast<int64_t>(lhs) - rhs; }

		/**
		 * \brief	Multiplication operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 * \exception	RuntimeException				Thrown when the given BigNumberBase object is in
		 * 												null state.
		 *
		 * \param	lhs	The first value to multiply.
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator*(const BigNumberBase& lhs, const BigNumberBase& rhs);

		/**
		 * \brief	Multiplication operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 * \exception	RuntimeException				Thrown when the given BigNumberBase object is in
		 * 												null state.
		 *
		 * \param	lhs	The first value to multiply.
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator*(const BigNumberBase& lhs, uint64_t rhs);
		inline BigNumber operator*(const BigNumberBase& lhs, uint32_t rhs) { return lhs * static_cast<uint64_t>(rhs); }
		inline BigNumber operator*(const BigNumberBase& lhs, uint16_t rhs) { return lhs * static_cast<uint64_t>(rhs); }
		inline BigNumber operator*(const BigNumberBase& lhs, uint8_t  rhs) { return lhs * static_cast<uint64_t>(rhs); }
		inline BigNumber operator*(uint64_t lhs, const BigNumberBase& rhs) { return rhs * lhs; }
		inline BigNumber operator*(uint32_t lhs, const BigNumberBase& rhs) { return static_cast<uint64_t>(lhs) * rhs; }
		inline BigNumber operator*(uint16_t lhs, const BigNumberBase& rhs) { return static_cast<uint64_t>(lhs) * rhs; }
		inline BigNumber operator*(uint8_t  lhs, const BigNumberBase& rhs) { return static_cast<uint64_t>(lhs) * rhs; }

		/**
		 * \brief	Division operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 * \exception	RuntimeException				Thrown when the given BigNumberBase object is in
		 * 												null state.
		 *
		 * \param	lhs	The numerator.
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator/(const BigNumberBase& lhs, const BigNumberBase& rhs);

		/**
		 * \brief	Division operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 * \exception	RuntimeException				Thrown when the given BigNumberBase object is in
		 * 												null state.
		 *
		 * \param	lhs	The numerator.
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator/(const BigNumberBase& lhs, int64_t  rhs);
		inline BigNumber operator/(const BigNumberBase& lhs, int32_t  rhs) { return lhs / static_cast<int64_t>(rhs); }
		inline BigNumber operator/(const BigNumberBase& lhs, int16_t  rhs) { return lhs / static_cast<int64_t>(rhs); }
		inline BigNumber operator/(const BigNumberBase& lhs, int8_t   rhs) { return lhs / static_cast<int64_t>(rhs); }
		inline BigNumber operator/(const BigNumberBase& lhs, uint32_t rhs) { return lhs / static_cast<int64_t>(rhs); }
		inline BigNumber operator/(const BigNumberBase& lhs, uint16_t rhs) { return lhs / static_cast<int64_t>(rhs); }
		inline BigNumber operator/(const BigNumberBase& lhs, uint8_t  rhs) { return lhs / static_cast<int64_t>(rhs); }

		/**
		 * \brief	Modulus operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 * \exception	RuntimeException				Thrown when the given BigNumberBase object is in
		 * 												null state.
		 *
		 * \param	lhs	The numerator.
		 * \param	rhs	The right hand side.
		 *
		 * \return	The result of the operation.
		 */
		BigNumber operator%(const BigNumberBase& lhs, const BigNumberBase& rhs);

		/**
		 * \brief	Bitwise left shift operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 * \exception	RuntimeException				Thrown when the given BigNumberBase object is in
		 * 												null state.
		 *
		 * \param	count	Number of bits to shift.
		 *
		 * \return	The shifted result.
		 */
		BigNumber operator<<(const BigNumberBase& lhs, uint64_t rhs);
		inline BigNumber operator<<(const BigNumberBase& lhs, uint32_t rhs) { return lhs << static_cast<uint64_t>(rhs); }
		inline BigNumber operator<<(const BigNumberBase& lhs, uint16_t rhs) { return lhs << static_cast<uint64_t>(rhs); }
		inline BigNumber operator<<(const BigNumberBase& lhs, uint8_t  rhs) { return lhs << static_cast<uint64_t>(rhs); }

		/**
		 * \brief	Bitwise right shift operator
		 *
		 * \exception	MbedTlsObj::MbedTlsException	Thrown when a MbedTls error returned.
		 * \exception	RuntimeException				Thrown when the given BigNumberBase object is in
		 * 												null state.
		 *
		 * \param	count	Number of bits to shift.
		 *
		 * \return	The shifted result.
		 */
		BigNumber operator>>(const BigNumberBase& lhs, uint64_t rhs);
		inline BigNumber operator>>(const BigNumberBase& lhs, uint32_t rhs) { return lhs >> static_cast<uint64_t>(rhs); }
		inline BigNumber operator>>(const BigNumberBase& lhs, uint16_t rhs) { return lhs >> static_cast<uint64_t>(rhs); }
		inline BigNumber operator>>(const BigNumberBase& lhs, uint8_t  rhs) { return lhs >> static_cast<uint64_t>(rhs); }
	}
}
