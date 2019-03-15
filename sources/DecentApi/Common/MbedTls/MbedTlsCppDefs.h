#pragma once

#include <array>
#include <vector>
#include <string>

namespace Decent
{
	namespace MbedTlsObj
	{
		/** \brief	Dummy struct to indicate the need for generating an object. Similar way can be found in std::unique_lock. */
		struct Generate
		{
			explicit Generate() = default;
		};
		constexpr Generate sk_gen;

		/** \brief	Dummy struct to indicate the need for creating an empty object. */
		struct Empty
		{
			explicit Empty() = default;
		};
		constexpr Empty sk_empty;

		/** \brief	Dummy struct to indicate a struct input. */
		struct StructIn
		{
			explicit StructIn() = default;
		};
		constexpr StructIn sk_struct;

		/** \brief	Dummy struct to indicate a big-endian input. */
		struct BigEndian
		{
			explicit BigEndian() = default;
		};
		constexpr BigEndian sk_bigEndian;

		constexpr int MBEDTLS_SUCCESS_RET = 0;

		enum class HashType
		{
			SHA224,
			SHA256,
			SHA384,
			SHA512,
		};

		namespace detail
		{
			//std::array
			template<typename T, size_t arrSize>
			T* GetPtr(std::array<T, arrSize>& arr)
			{
				return arr.data();
			}

			template<typename T, size_t arrSize>
			constexpr size_t GetSize(const std::array<T, arrSize>&)
			{
				return arrSize * sizeof(T);
			}

			template<typename T, size_t arrSize>
			const T* GetPtr(const std::array<T, arrSize>& arr)
			{
				return arr.data();
			}

			//C array
			template<typename T, size_t arrSize>
			constexpr T* GetPtr(T (&arr)[arrSize])
			{
				return arr;
			}

			template<typename T, size_t arrSize>
			constexpr size_t GetSize(T (&)[arrSize])
			{
				return arrSize * sizeof(T);
			}

			template<typename T, size_t arrSize>
			constexpr const T* GetPtr(const T (&arr)[arrSize])
			{
				return arr;
			}

			//std::vector
			template<typename T>
			T* GetPtr(std::vector<T>& arr)
			{
				return arr.data();
			}

			template<typename T>
			size_t GetSize(const std::vector<T>& arr)
			{
				return arr.size() * sizeof(T);
			}

			template<typename T>
			const T* GetPtr(const std::vector<T>& arr)
			{
				return arr.data();
			}

			//std::basic_string
			template<class _Elem, class _Traits, class _Alloc>
			typename std::basic_string<_Elem, _Traits, _Alloc>::value_type* GetPtr(std::basic_string<_Elem, _Traits, _Alloc>& arr)
			{
				return &arr[0];
			}

			template<class _Elem, class _Traits, class _Alloc>
			size_t GetSize(const std::basic_string<_Elem, _Traits, _Alloc>& arr)
			{
				return arr.size() * sizeof(typename std::basic_string<_Elem, _Traits, _Alloc>::value_type);
			}

			template<class _Elem, class _Traits, class _Alloc>
			const typename std::basic_string<_Elem, _Traits, _Alloc>::value_type* GetPtr(const std::basic_string<_Elem, _Traits, _Alloc>& arr)
			{
				return arr.data();
			}
		}
	}
}
