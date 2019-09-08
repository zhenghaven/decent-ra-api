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

		/**
		 * \brief	The value returned by MbedTLS to indicate a successful function call.
		 */
		constexpr int MBEDTLS_SUCCESS_RET = 0;

		/**
		 * \brief	Number of bits per Byte
		 */
		constexpr uint8_t BITS_PER_BYTE = 8;

		/** \brief	Values that represent hash types */
		enum class HashType
		{
			SHA224,
			SHA256,
			SHA384,
			SHA512,
		};

		/** \brief	Values that represent cipher types */
		enum class CipherType
		{
			AES,
		};

		/** \brief	Values that represent cipher modes */
		enum class CipherMode
		{
			ECB,
			CBC,
			CTR,
			GCM,
		};

		/** \brief	An item in data list, which is used in batched calculations. */
		struct DataListItem
		{
			const void* m_ptr;
			const size_t m_size;
		};

		namespace detail
		{
			//#################################################
			//#      std::array
			//#################################################

			template<typename T, size_t arrSize>
			T* GetPtr(std::array<T, arrSize>& arr)
			{
				return arr.data();
			}

			template<typename T, size_t arrSize>
			const T* GetPtr(const std::array<T, arrSize>& arr)
			{
				return arr.data();
			}

			template<typename T, size_t arrSize>
			constexpr size_t GetValSize(const std::array<T, arrSize>&)
			{
				return sizeof(T);
			}

			template<typename T, size_t arrSize>
			constexpr size_t GetSize(const std::array<T, arrSize>&)
			{
				return arrSize * sizeof(T);
			}

			//#################################################
			//#      C array
			//#################################################

			template<typename T, size_t arrSize>
			constexpr T* GetPtr(T(&arr)[arrSize])
			{
				return arr;
			}

			template<typename T, size_t arrSize>
			constexpr const T* GetPtr(const T(&arr)[arrSize])
			{
				return arr;
			}

			template<typename T, size_t arrSize>
			constexpr size_t GetValSize(const T(&)[arrSize])
			{
				return sizeof(T);
			}

			template<typename T, size_t arrSize>
			constexpr size_t GetSize(T(&)[arrSize])
			{
				return arrSize * sizeof(T);
			}

			//#################################################
			//#      std::vector
			//#################################################

			template<typename T>
			T* GetPtr(std::vector<T>& arr)
			{
				return arr.data();
			}

			template<typename T>
			const T* GetPtr(const std::vector<T>& arr)
			{
				return arr.data();
			}

			template<typename T>
			constexpr size_t GetValSize(const std::vector<T>&)
			{
				return sizeof(T);
			}

			template<typename T>
			size_t GetSize(const std::vector<T>& arr)
			{
				return arr.size() * sizeof(T);
			}

			template<typename T>
			void Resize(std::vector<T>& arr, size_t byteSize)
			{
				constexpr size_t valSize = sizeof(T);

				size_t sizeNeeded = (byteSize / valSize) + (byteSize % valSize == 0 ? 0 : 1);

				return arr.resize(sizeNeeded);
			}

			//#################################################
			//#      std::basic_string
			//#################################################

			template<class _Elem, class _Traits, class _Alloc>
			typename std::basic_string<_Elem, _Traits, _Alloc>::value_type* GetPtr(std::basic_string<_Elem, _Traits, _Alloc>& arr)
			{
				return &arr[0];
			}

			template<class _Elem, class _Traits, class _Alloc>
			const typename std::basic_string<_Elem, _Traits, _Alloc>::value_type* GetPtr(const std::basic_string<_Elem, _Traits, _Alloc>& arr)
			{
				return arr.data();
			}

			template<class _Elem, class _Traits, class _Alloc>
			constexpr size_t GetValSize(const std::basic_string<_Elem, _Traits, _Alloc>&)
			{
				return sizeof(typename std::basic_string<_Elem, _Traits, _Alloc>::value_type);
			}

			template<class _Elem, class _Traits, class _Alloc>
			size_t GetSize(const std::basic_string<_Elem, _Traits, _Alloc>& arr)
			{
				return arr.size() * sizeof(typename std::basic_string<_Elem, _Traits, _Alloc>::value_type);
			}

			template<class _Elem, class _Traits, class _Alloc>
			void Resize(std::basic_string<_Elem, _Traits, _Alloc>& arr, size_t byteSize)
			{
				constexpr size_t valSize = sizeof(typename std::basic_string<_Elem, _Traits, _Alloc>::value_type);

				size_t sizeNeeded = (byteSize / valSize) + (byteSize % valSize == 0 ? 0 : 1);

				return arr.resize(sizeNeeded);
			}
		}

		namespace detail
		{
			template<typename T>
			inline constexpr DataListItem ConstructDataListItem(const T& data)
			{
				return DataListItem{ GetPtr(data), GetSize(data) };
			}

			template<class... Args>
			inline constexpr std::array<DataListItem, sizeof...(Args)> ConstructDataList(const Args&... args)
			{
				return std::array<DataListItem, sizeof...(Args)>{ ConstructDataListItem(args)... };
			}
		}
	}
}
