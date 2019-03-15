#include "BigNumber.h"

#include <cstring>

#include <type_traits>

#include <mbedtls/bignum.h>

#include "MbedTlsException.h"
#include "Drbg.h"

using namespace Decent::MbedTlsObj;

#define CHECK_MBEDTLS_RET(VAL) { int retVal = VAL; if(retVal != MBEDTLS_SUCCESS_RET) { throw MbedTlsException(__FUNCTION__, retVal); } }

void BigNumber::FreeObject(mbedtls_mpi* ptr)
{
	mbedtls_mpi_free(ptr);
	delete ptr;
}

BigNumber BigNumber::Rand(size_t size)
{
	BigNumber res(sk_empty);

	Drbg drbg;

	CHECK_MBEDTLS_RET(mbedtls_mpi_fill_random(res.Get(), size, &Drbg::CallBack, &drbg));

	return std::move(res);
}

std::string BigNumber::ToHexStr(uint8_t num) noexcept
{
	static constexpr char const hexLUT[] = "0123456789ABCDEF";

	char res[] = { hexLUT[(num >> 4) & 0xF], hexLUT[num & 0xF], '\0' };

	return res;
}

std::string BigNumber::ToHexStr(const void * ptr, const size_t size, const BigEndian&)
{
	const uint8_t* bytePtr = static_cast<const uint8_t*>(ptr);
	std::string res;
	res.reserve(size * 2);

	for (int64_t i = size - 1; i >= 0; --i)
	{
		res.append(ToHexStr(bytePtr[i]));
	}

	return std::move(res);
}

BigNumber::BigNumber(const Empty &) :
	ObjBase(new mbedtls_mpi, &FreeObject)
{
	mbedtls_mpi_init(Get());
}

BigNumber::BigNumber(const void * ptr, const size_t size) :
	BigNumber(sk_empty)
{
	int extraLimb = (size % sizeof(mbedtls_mpi_uint)) ? 1 : 0;
	size_t totalLimbs = (size / sizeof(mbedtls_mpi_uint)) + extraLimb;
	CHECK_MBEDTLS_RET(mbedtls_mpi_grow(Get(), totalLimbs));

	memcpy(Get()->p, ptr, size);
}

BigNumber::BigNumber(const void * ptr, const size_t size, const BigEndian &) :
	BigNumber(sk_empty)
{
	const uint8_t* inByte = static_cast<const uint8_t*>(ptr);
	CHECK_MBEDTLS_RET(mbedtls_mpi_read_binary(Get(), inByte, size));
}

BigNumber::BigNumber(const mbedtls_mpi & rhs) :
	ObjBase(new mbedtls_mpi, &FreeObject)
{
	mbedtls_mpi_init(Get());

	CHECK_MBEDTLS_RET(mbedtls_mpi_copy(Get(), &rhs));
}

BigNumber::BigNumber(const BigNumber & rhs) :
	BigNumber(*rhs.Get())
{
}

BigNumber::BigNumber(const ConstBigNumber & rhs) :
	BigNumber(*static_cast<const BigNumber&>(rhs).Get())
{
}

int BigNumber::Compare(const BigNumber & rhs) const noexcept
{
	return mbedtls_mpi_cmp_mpi(Get(), rhs.Get());
}

BigNumber & BigNumber::operator=(const BigNumber & rhs)
{
	if (this != &rhs)
	{
		CHECK_MBEDTLS_RET(mbedtls_mpi_copy(Get(), rhs.Get()));
	}
	return *this;
}

BigNumber BigNumber::operator+(const BigNumber & rhs) const
{
	BigNumber res(sk_empty);

	CHECK_MBEDTLS_RET(mbedtls_mpi_add_mpi(res.Get(), Get(), rhs.Get()));

	return std::move(res);
}

BigNumber BigNumber::operator+(int64_t rhs) const
{
	static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit numbers.");

	BigNumber res(sk_empty);

	CHECK_MBEDTLS_RET(mbedtls_mpi_add_int(res.Get(), Get(), rhs));

	return std::move(res);
}

BigNumber& BigNumber::operator+=(const BigNumber & rhs)
{
	BigNumber res = (*this + rhs);

	this->Swap(res);

	return *this;
}

BigNumber & BigNumber::operator+=(int64_t rhs)
{
	BigNumber res = (*this + rhs);

	this->Swap(res);

	return *this;
}

BigNumber BigNumber::operator-(const BigNumber & rhs) const
{
	BigNumber res(sk_empty);

	CHECK_MBEDTLS_RET(mbedtls_mpi_sub_mpi(res.Get(), Get(), rhs.Get()));

	return std::move(res);
}

BigNumber BigNumber::operator-(int64_t rhs) const
{
	static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit numbers.");

	BigNumber res(sk_empty);

	CHECK_MBEDTLS_RET(mbedtls_mpi_sub_int(res.Get(), Get(), rhs));

	return std::move(res);
}

BigNumber & BigNumber::operator-=(const BigNumber & rhs)
{
	BigNumber res = (*this - rhs);

	this->Swap(res);

	return *this;
}

BigNumber & BigNumber::operator-=(int64_t rhs)
{
	BigNumber res = (*this - rhs);

	this->Swap(res);

	return *this;
}

BigNumber BigNumber::operator*(const BigNumber & rhs) const
{
	BigNumber res(sk_empty);

	CHECK_MBEDTLS_RET(mbedtls_mpi_mul_mpi(res.Get(), Get(), rhs.Get()));

	return std::move(res);
}

BigNumber BigNumber::operator*(uint64_t rhs) const
{
	static_assert(std::is_same<mbedtls_mpi_uint, uint64_t>::value, "Currently, we only consider 64-bit numbers.");

	BigNumber res(sk_empty);

	CHECK_MBEDTLS_RET(mbedtls_mpi_mul_int(res.Get(), Get(), rhs));

	return std::move(res);
}

BigNumber & BigNumber::operator*=(const BigNumber & rhs)
{
	BigNumber res = (*this * rhs);

	this->Swap(res);

	return *this;
}

BigNumber & BigNumber::operator*=(uint64_t rhs)
{
	BigNumber res = (*this * rhs);

	this->Swap(res);

	return *this;
}

BigNumber BigNumber::operator/(const BigNumber & rhs) const
{
	BigNumber res(sk_empty);

	CHECK_MBEDTLS_RET(mbedtls_mpi_div_mpi(res.Get(), nullptr, Get(), rhs.Get()));

	return std::move(res);
}

BigNumber BigNumber::operator/(int64_t rhs) const
{
	static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit numbers.");

	BigNumber res(sk_empty);

	CHECK_MBEDTLS_RET(mbedtls_mpi_div_int(res.Get(), nullptr, Get(), rhs));

	return std::move(res);
}

BigNumber & BigNumber::operator/=(const BigNumber & rhs)
{
	BigNumber res = (*this / rhs);

	this->Swap(res);

	return *this;
}

BigNumber & BigNumber::operator/=(int64_t rhs)
{
	BigNumber res = (*this / rhs);

	this->Swap(res);

	return *this;
}

BigNumber BigNumber::operator%(const BigNumber & rhs) const
{
	BigNumber res(sk_empty);

	CHECK_MBEDTLS_RET(mbedtls_mpi_mod_mpi(res.Get(), Get(), rhs.Get()));

	return std::move(res);
}

uint64_t BigNumber::operator%(int64_t rhs) const
{
	static_assert(std::is_same<mbedtls_mpi_sint, int64_t>::value, "Currently, we only consider 64-bit numbers.");

	uint64_t res = 0;
	CHECK_MBEDTLS_RET(mbedtls_mpi_mod_int(&res, Get(), rhs));

	return res;
}

BigNumber BigNumber::operator-() const
{
	BigNumber cpy(*this);
	cpy.FlipSign();
	return std::move(cpy);
}

BigNumber BigNumber::operator<<(size_t count) const
{
	BigNumber res(*this);
	res <<= count;
	return std::move(res);
}

BigNumber Decent::MbedTlsObj::BigNumber::operator>>(size_t count) const
{
	BigNumber res(*this);
	res >>= count;
	return std::move(res);
}

BigNumber & BigNumber::operator%=(const BigNumber & rhs)
{
	BigNumber res = (*this % rhs);

	this->Swap(res);

	return *this;
}

BigNumber & BigNumber::operator%=(int64_t rhs)
{
	BigNumber res((*this % rhs), sk_struct);

	this->Swap(res);

	return *this;
}

BigNumber & BigNumber::operator<<=(size_t count)
{
	CHECK_MBEDTLS_RET(mbedtls_mpi_shift_l(Get(), count));

	return *this;
}

BigNumber & BigNumber::operator>>=(size_t count)
{
	CHECK_MBEDTLS_RET(mbedtls_mpi_shift_r(Get(), count));

	return *this;
}

bool BigNumber::operator==(const BigNumber & rhs) const
{
	return Compare(rhs) == 0;
}

bool BigNumber::operator!=(const BigNumber & rhs) const
{
	return Compare(rhs) != 0;
}

bool BigNumber::operator<(const BigNumber & rhs) const
{
	return Compare(rhs) < 0;
}

bool BigNumber::operator<=(const BigNumber & rhs) const
{
	return Compare(rhs) <= 0;
}

bool BigNumber::operator>(const BigNumber & rhs) const
{
	return Compare(rhs) > 0;
}

bool BigNumber::operator>=(const BigNumber & rhs) const
{
	return Compare(rhs) >= 0;
}

size_t BigNumber::GetSize() const
{
	return *this ? mbedtls_mpi_size(Get()) : 0;
}

size_t BigNumber::GetBitSize() const
{
	return *this ? mbedtls_mpi_bitlen(Get()) : 0;
}

void BigNumber::ToBinary(void * out, const size_t size) const
{
	size_t actualSize = GetSize();
	if (size < actualSize) { throw MbedTlsException(__FUNCTION__, MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL); }

	memset(out, 0, size);

	memcpy(out, Get()->p, actualSize);
}

void BigNumber::ToBinary(void * out, const size_t size, const BigEndian &) const
{
	uint8_t* outByte = static_cast<uint8_t*>(out);
	CHECK_MBEDTLS_RET(mbedtls_mpi_write_binary(Get(), outByte, size));
}

std::string BigNumber::ToBigEndianHexStr() const
{
	return ToHexStr(Get()->p, Get()->n * sizeof(mbedtls_mpi_uint), sk_bigEndian);
}

bool BigNumber::IsPositive() const
{
	return Get()->s > 0;
}

BigNumber& BigNumber::FlipSign()
{
	Get()->s *= -1;
	return *this;
}

BigNumber & BigNumber::SetBit(const size_t pos, bool bit)
{
	CHECK_MBEDTLS_RET(mbedtls_mpi_set_bit(Get(), pos, bit ? 1 : 0));

	return *this;
}

bool BigNumber::GetBit(const size_t pos)
{
	return mbedtls_mpi_get_bit(Get(), pos) == 1;
}

void ConstBigNumber::FreeStruct(mbedtls_mpi * ptr)
{
	delete ptr;
}

ConstBigNumber::ConstBigNumber(const BigNumber & ref) noexcept :
	ConstBigNumber(*ref.Get())
{
}

ConstBigNumber::ConstBigNumber(mbedtls_mpi & ref) noexcept :
	m_bigNum(&ref, &BigNumber::DoNotFree)
{
}

ConstBigNumber::ConstBigNumber(const void * ptr, const size_t size) :
	ConstBigNumber(ptr,
	(size % sizeof(mbedtls_mpi_uint)) ?
		throw RuntimeException("The size of the given big number must be a factor of " + std::to_string(sizeof(mbedtls_mpi_uint)) + ". ") :
		size,
		sk_gen)
{}

ConstBigNumber::operator const BigNumber&() const noexcept
{
	return m_bigNum;
}

const BigNumber & ConstBigNumber::Get() const noexcept
{
	return m_bigNum;
}

ConstBigNumber::ConstBigNumber(const void * ptr, const size_t size, const Generate &) noexcept :
	m_bigNum(new mbedtls_mpi{1, /* s */
		(size / sizeof(mbedtls_mpi_uint)), /* n */
		static_cast<mbedtls_mpi_uint*>(const_cast<void*>(ptr)) /* p */
		}, &ConstBigNumber::FreeStruct)
{
}

