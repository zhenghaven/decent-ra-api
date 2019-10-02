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

		/** \brief	Values that represent asymmetric algorithm types */
		enum class AsymAlgmType
		{
			EC,
			RSA,
		};
		
		/** \brief	Values that represent asymmetric key types */
		enum class AsymKeyType
		{
			Public,
			Private,
		};

		enum class EcKeyType
		{
			SECP192R1,
			SECP224R1,
			SECP256R1,
			SECP384R1,
			SECP521R1,
			BP256R1,
			BP384R1,
			BP512R1,
			SECP192K1,
			SECP224K1,
			SECP256K1,
		};

		/** \brief	An item in data list, which is used in batched calculations. */
		struct DataListItem
		{
			const void* m_ptr;
			const size_t m_size;
		};

		namespace detail
		{
			template<class T>
			struct remove_cvref
			{
				typedef typename std::remove_cv<typename std::remove_reference<T>::type >::type type;
			};

			struct NotSupportedContainerType
			{
				static constexpr bool sk_isSprtCtn = false;
			};

			struct SupportedContainerType
			{
				static constexpr bool sk_isSprtCtn = true;
			};

			template<class T, size_t arrLen>
			struct StaticContainerSize : SupportedContainerType
			{
				static constexpr bool sk_isStaticSize = true;

				static constexpr size_t sk_len = arrLen;
				static constexpr size_t sk_valSize = sizeof(T);
				static constexpr size_t sk_ctnSize = sk_valSize * sk_len;

				typedef T ValType;
			};

			template<class T>
			struct DynContainerSize : SupportedContainerType
			{
				static constexpr bool sk_isStaticSize = false;

				static constexpr size_t sk_valSize = sizeof(T);

				typedef T ValType;
			};

			//#################################################
			//#      Static Container Properties
			//#################################################
			
			template<class ContainerType>
			struct StaticContainerPrpt;

			template<typename T, size_t arrLen>
			struct StaticContainerPrpt<std::array<T, arrLen> >
				: StaticContainerSize<T, arrLen>
			{
				static inline void ResizeIfDyn(std::array<T, arrLen>& ctn, size_t size)
				{}
			};

			template<typename T, size_t arrLen>
			struct StaticContainerPrpt<T[arrLen]>
				: StaticContainerSize<T, arrLen>
			{
				static inline void ResizeIfDyn(T(&ctn)[arrLen], size_t size)
				{}
			};

			//#################################################
			//#      Dynamic Container Properties
			//#################################################

			template<class ContainerType>
			struct DynContainerPrpt;

			template<typename T>
			struct DynContainerPrpt<std::vector<T> >
				: DynContainerSize<T>
			{
				static inline void ResizeIfDyn(std::vector<T>& ctn, size_t size)
				{
					ctn.resize(size);
				}
			};

			template<class _Elem, class _Traits, class _Alloc>
			struct DynContainerPrpt<std::basic_string<_Elem, _Traits, _Alloc> >
				: DynContainerSize<typename std::basic_string<_Elem, _Traits, _Alloc>::value_type>
			{
				static inline void ResizeIfDyn(std::basic_string<_Elem, _Traits, _Alloc>& ctn, size_t size)
				{
					constexpr size_t valSize = sizeof(typename std::basic_string<_Elem, _Traits, _Alloc>::value_type);

					size_t sizeNeeded = (size / valSize) + (size % valSize == 0 ? 0 : 1);

					return ctn.resize(sizeNeeded);
				}
			};

			//#################################################
			//#      Combined Container Properties
			//#################################################

			template<typename ContainerType>
			struct ContainerPrpt : NotSupportedContainerType {};

			template<typename T, size_t arrLen>
			struct ContainerPrpt<std::array<T, arrLen> > : StaticContainerPrpt<std::array<T, arrLen> >
			{};

			template<typename T, size_t arrLen>
			struct ContainerPrpt<T[arrLen]> : StaticContainerPrpt<T[arrLen]>
			{};

			template<typename T>
			struct ContainerPrpt<std::vector<T> > : DynContainerPrpt<std::vector<T> >
			{};

			template<class _Elem, class _Traits, class _Alloc>
			struct ContainerPrpt<std::basic_string<_Elem, _Traits, _Alloc> > : DynContainerPrpt<std::basic_string<_Elem, _Traits, _Alloc> >
			{};

			//#################################################
			//#      Some Helpers
			//#################################################

			template<typename T, size_t expectedSize>
			struct DynCtnOrStatCtnWithSize
			{
				static constexpr bool value = ContainerPrpt<T>::sk_isSprtCtn && // It's supported type
					(!ContainerPrpt<T>::sk_isStaticSize || // It's dynamic container
						ContainerPrpt<T>::sk_ctnSize == expectedSize); // OR, it is static container with expected size.
			};

			template<typename T, size_t expectedSize>
			struct StatCtnWithSize
			{
				static constexpr bool value = ContainerPrpt<T>::sk_isSprtCtn && // It's supported type
					(ContainerPrpt<T>::sk_isStaticSize && // It's static container
						ContainerPrpt<T>::sk_ctnSize == expectedSize); // AND, it has expected size.
			};
		}

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
