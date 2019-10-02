#include "BigNumber.h"

#include <cstring>

#include <type_traits>

#include <mbedtls/bignum.h>

#include "MbedTlsException.h"
#include "RbgBase.h"

using namespace Decent::MbedTlsObj;

//================================================================================================
//  BigNumberBase
//================================================================================================

namespace
{
	static constexpr char const gsk_hexLUT[] = "0123456789ABCDEF";

	static constexpr char HiBitHex(uint8_t byte)
	{
		return gsk_hexLUT[(byte >> 4) & 0xF];
	}

	static constexpr char LoBitHex(uint8_t byte)
	{
		return gsk_hexLUT[byte & 0xF];
	}

	template<uint8_t byte>
	struct StaticByteToHex
	{
		static constexpr char const sk_val[] = { HiBitHex(byte), LoBitHex(byte), '\0' };
	};

	static std::string ByteToHexStr(uint8_t byte)
	{
		return std::string({ HiBitHex(byte), LoBitHex(byte) });
	}
}

std::string BigNumberBase::BytesToBigEndianHexStr(const void * ptr, const size_t size)
{
	const uint8_t* bytePtr = static_cast<const uint8_t*>(ptr);
	std::string res;
	res.reserve(size * 2);

	for (int64_t i = size - 1; i >= 0; --i)
	{
		res.append(ByteToHexStr(bytePtr[i]));
	}

	return res;
}

void BigNumberBase::FreeObject(mbedtls_mpi* ptr)
{
	mbedtls_mpi_free(ptr);
	delete ptr;
}

BigNumberBase::BigNumberBase() :
	ObjBase(new mbedtls_mpi, &FreeObject)
{
	mbedtls_mpi_init(Get());
}

BigNumberBase::BigNumberBase(const BigNumberBase & rhs) :
	ObjBase(rhs.Get() ? new mbedtls_mpi : nullptr, rhs.Get() ? &FreeObject : &DoNotFree)
{
	if (rhs.Get())
	{
		mbedtls_mpi_init(Get());
		CALL_MBEDTLS_C_FUNC(mbedtls_mpi_copy, Get(), rhs.Get());
	}
}

BigNumberBase::BigNumberBase(BigNumberBase && rhs) :
	ObjBase(std::forward<ObjBase>(rhs))
{
}

BigNumberBase::~BigNumberBase()
{
}

BigNumberBase & BigNumberBase::operator=(BigNumberBase && rhs)
{
	ObjBase::operator=(std::forward<ObjBase>(rhs));

	return *this;
}

bool BigNumberBase::IsPositive() const
{
	NullCheck();

	return Get()->s > 0;
}

size_t BigNumberBase::GetSize() const
{
	NullCheck();
	return mbedtls_mpi_size(Get());
}

size_t BigNumberBase::GetBitSize() const
{
	NullCheck();
	return mbedtls_mpi_bitlen(Get());
}

bool BigNumberBase::GetBit(const size_t pos) const
{
	NullCheck();

	return mbedtls_mpi_get_bit(Get(), pos) == 1;
}

std::string BigNumberBase::ToBigEndianHexStr() const
{
	NullCheck();

	return BytesToBigEndianHexStr(Get()->p, Get()->n * sizeof(mbedtls_mpi_uint));
}

int BigNumberBase::Compare(const BigNumberBase & rhs) const
{
	NullCheck();
	rhs.NullCheck();
	return mbedtls_mpi_cmp_mpi(Get(), rhs.Get());
}

bool BigNumberBase::operator==(const BigNumberBase & rhs) const
{
	return Compare(rhs) == 0;
}

bool BigNumberBase::operator!=(const BigNumberBase & rhs) const
{
	return Compare(rhs) != 0;
}

bool BigNumberBase::operator<(const BigNumberBase & rhs) const
{
	return Compare(rhs) < 0;
}

bool BigNumberBase::operator<=(const BigNumberBase & rhs) const
{
	return Compare(rhs) <= 0;
}

bool BigNumberBase::operator>(const BigNumberBase & rhs) const
{
	return Compare(rhs) > 0;
}

bool BigNumberBase::operator>=(const BigNumberBase & rhs) const
{
	return Compare(rhs) >= 0;
}

uint64_t BigNumberBase::operator%(int64_t rhs) const
{
	static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit machines.");

	NullCheck();

	uint64_t res = 0;
	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_mod_int, &res, Get(), rhs);

	return res;
}

BigNumberBase::BigNumberBase(mbedtls_mpi * ptr, FreeFuncType freeFunc) :
	ObjBase(ptr, freeFunc)
{
}

void BigNumberBase::InternalToBinary(void * out, const size_t size) const
{
	NullCheck();

	size_t actualSize = Get()->n * sizeof(mbedtls_mpi_uint);
	if (actualSize <= size || (actualSize = GetSize()) <= size)
	{
		memcpy(out, Get()->p, actualSize);

		memset(static_cast<uint8_t*>(out) + actualSize, 0, size - actualSize);

		return;
	}

	throw MbedTlsException("ConstBigNumber::ToBinary", MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL);
}

void BigNumberBase::InternalToBigEndianBinary(void * out, const size_t size) const
{
	NullCheck();

	uint8_t* outByte = static_cast<uint8_t*>(out);
	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_write_binary, Get(), outByte, size);
}

//================================================================================================
//  ConstBigNumber
//================================================================================================

void ConstBigNumber::FreeDummyMpi(mbedtls_mpi * ptr)
{
	delete ptr;
}

ConstBigNumber::ConstBigNumber(ConstBigNumber && rhs) :
	BigNumberBase(std::forward<BigNumberBase>(rhs))
{}

ConstBigNumber::~ConstBigNumber()
{}

ConstBigNumber & ConstBigNumber::operator=(ConstBigNumber && rhs)
{
	BigNumberBase::operator=(std::forward<BigNumberBase>(rhs));

	return *this;
}

ConstBigNumber::ConstBigNumber(const void * ptr, const size_t size) :
	ConstBigNumber(ptr,
	(size % sizeof(mbedtls_mpi_uint)) == 0 ?
		size :
		throw RuntimeException("The size of the buffer given to ConstBigNumber must be a factor of " "8" "."),
		sk_gen)
{}

ConstBigNumber::ConstBigNumber(const void * ptr, const size_t size, const Generate &) :
	BigNumberBase(
		new mbedtls_mpi{
			/* s */ 1,
			/* n */ (size / sizeof(mbedtls_mpi_uint)),
			/* p */ static_cast<mbedtls_mpi_uint*>(const_cast<void*>(ptr))
		},
		&FreeDummyMpi)
{}

//================================================================================================
//  BigNumber
//================================================================================================

BigNumber::BigNumber() :
	BigNumberBase()
{}

BigNumber::BigNumber(BigNumber && rhs) :
	BigNumberBase(std::forward<BigNumberBase>(rhs))
{}

BigNumber::BigNumber(const BigNumberBase & rhs) :
	BigNumberBase(rhs)
{}

BigNumber::BigNumber(mbedtls_mpi & ref) :
	BigNumberBase(&ref, &DoNotFree)
{
}

BigNumber::BigNumber(size_t size, RbgBase & rbg) :
	BigNumber()
{
	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_fill_random, Get(), size, &RbgBase::CallBack, &rbg);
}

BigNumber::BigNumber(size_t size, std::unique_ptr<RbgBase> rbg) :
	BigNumber(size, *rbg)
{
}

BigNumber::~BigNumber()
{
}

// Protected constructors:

BigNumber::BigNumber(const void * ptr, const size_t size, bool isPositive) :
	BigNumber()
{
	int extraLimb = (size % sizeof(mbedtls_mpi_uint)) ? 1 : 0;
	size_t totalLimbs = (size / sizeof(mbedtls_mpi_uint)) + extraLimb;
	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_grow, Get(), totalLimbs);

	memcpy(Get()->p, ptr, size);

	Get()->s = isPositive ? 1 : -1;
}

BigNumber::BigNumber(const BigEndian &, const void * ptr, const size_t size, bool isPositive) :
	BigNumber()
{
	const uint8_t* inByte = static_cast<const uint8_t*>(ptr);
	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_read_binary, Get(), inByte, size);

	Get()->s = isPositive ? 1 : -1;
}

//Other methods:

BigNumber & BigNumber::operator=(const BigNumberBase & rhs)
{
	if (this != &rhs)
	{
		NullCheck();
		rhs.NullCheck();

		CALL_MBEDTLS_C_FUNC(mbedtls_mpi_copy, Get(), rhs.Get());
	}
	return *this;
}

BigNumber & BigNumber::operator=(BigNumber && rhs)
{
	BigNumberBase::operator=(std::forward<BigNumberBase>(rhs));
	return *this;
}

void BigNumber::SwapContent(BigNumber & other)
{
	NullCheck();
	other.NullCheck();

	mbedtls_mpi_swap(Get(), other.Get());
}

BigNumber & BigNumber::operator=(int64_t rhs)
{
	static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit numbers.");

	NullCheck();

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_lset, Get(), rhs);

	return *this;
}

BigNumber& BigNumber::operator+=(const BigNumberBase & rhs)
{
	NullCheck();
	rhs.NullCheck();

	BigNumber res = (*this + rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator+=(int64_t rhs)
{
	NullCheck();

	BigNumber res = (*this + rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator-=(const BigNumberBase & rhs)
{
	NullCheck();
	rhs.NullCheck();

	BigNumber res = (*this - rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator-=(int64_t rhs)
{
	NullCheck();

	BigNumber res = (*this - rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator*=(const BigNumberBase & rhs)
{
	NullCheck();
	rhs.NullCheck();

	BigNumber res = (*this * rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator*=(uint64_t rhs)
{
	NullCheck();

	BigNumber res = (*this * rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator/=(const BigNumberBase & rhs)
{
	NullCheck();
	rhs.NullCheck();

	BigNumber res = (*this / rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator/=(int64_t rhs)
{
	NullCheck();

	BigNumber res = (*this / rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator%=(const BigNumberBase & rhs)
{
	NullCheck();
	rhs.NullCheck();

	BigNumber res = (*this % rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator%=(int64_t rhs)
{
	NullCheck();

	BigNumber res = (*this % rhs);

	BigNumber::SwapContent(res);

	return *this;
}

BigNumber & BigNumber::operator<<=(uint64_t rhs)
{
	static_assert(std::is_same<size_t, uint64_t>::value, "Current implementation assume size_t is same as uint64_t.");

	NullCheck();

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_shift_l, Get(), rhs);

	return *this;
}

BigNumber & BigNumber::operator>>=(uint64_t rhs)
{
	static_assert(std::is_same<size_t, uint64_t>::value, "Current implementation assume size_t is same as uint64_t.");

	NullCheck();

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_shift_r, Get(), rhs);

	return *this;
}

BigNumber& BigNumber::FlipSign()
{
	NullCheck();

	Get()->s *= -1;
	return *this;
}

BigNumber & BigNumber::SetBit(const size_t pos, bool bit)
{
	NullCheck();

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_set_bit, Get(), pos, bit ? 1 : 0);

	return *this;
}

//================================================================================================
//  Static Operators
//================================================================================================

BigNumber Decent::MbedTlsObj::operator-(const BigNumberBase & rhs)
{
	BigNumber cpy(rhs);
	cpy.FlipSign();
	return cpy;
}

BigNumber Decent::MbedTlsObj::operator+(const BigNumberBase & lhs, const BigNumberBase & rhs)
{
	lhs.NullCheck();
	rhs.NullCheck();

	BigNumber res;

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_add_mpi, res.Get(), lhs.Get(), rhs.Get());

	return res;
}

BigNumber Decent::MbedTlsObj::operator+(const BigNumberBase & lhs, int64_t rhs)
{
	static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit numbers.");

	lhs.NullCheck();

	BigNumber res;

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_add_int, res.Get(), lhs.Get(), rhs);

	return res;
}

BigNumber Decent::MbedTlsObj::operator-(const BigNumberBase & lhs, const BigNumberBase & rhs)
{
	lhs.NullCheck();
	rhs.NullCheck();

	BigNumber res;

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_sub_mpi, res.Get(), lhs.Get(), rhs.Get());

	return res;
}

BigNumber Decent::MbedTlsObj::operator-(const BigNumberBase & lhs, int64_t rhs)
{
	static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit numbers.");

	lhs.NullCheck();

	BigNumber res;

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_sub_int, res.Get(), lhs.Get(), rhs);

	return res;
}

BigNumber Decent::MbedTlsObj::operator*(const BigNumberBase & lhs, const BigNumberBase & rhs)
{
	lhs.NullCheck();
	rhs.NullCheck();

	BigNumber res;

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_mul_mpi, res.Get(), lhs.Get(), rhs.Get());

	return res;
}

BigNumber Decent::MbedTlsObj::operator*(const BigNumberBase & lhs, uint64_t rhs)
{
	static_assert(std::is_same<mbedtls_mpi_uint, uint64_t>::value, "Currently, we only consider 64-bit numbers.");

	lhs.NullCheck();

	BigNumber res;

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_mul_int, res.Get(), lhs.Get(), rhs);

	return res;
}

BigNumber Decent::MbedTlsObj::operator/(const BigNumberBase & lhs, const BigNumberBase & rhs)
{
	lhs.NullCheck();
	rhs.NullCheck();

	BigNumber res;

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_div_mpi, res.Get(), nullptr, lhs.Get(), rhs.Get());

	return res;
}

BigNumber Decent::MbedTlsObj::operator/(const BigNumberBase & lhs, int64_t rhs)
{
	static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit numbers.");

	lhs.NullCheck();

	BigNumber res;

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_div_int, res.Get(), nullptr, lhs.Get(), rhs);

	return res;
}

BigNumber Decent::MbedTlsObj::operator%(const BigNumberBase & lhs, const BigNumberBase & rhs)
{
	lhs.NullCheck();
	rhs.NullCheck();

	BigNumber res;

	CALL_MBEDTLS_C_FUNC(mbedtls_mpi_mod_mpi, res.Get(), lhs.Get(), rhs.Get());

	return res;
}

BigNumber Decent::MbedTlsObj::operator<<(const BigNumberBase & lhs, uint64_t rhs)
{
	BigNumber res(lhs);
	res <<= rhs;
	return res;
}

BigNumber Decent::MbedTlsObj::operator>>(const BigNumberBase & lhs, uint64_t rhs)
{
	BigNumber res(lhs);
	res >>= rhs;
	return res;
}
