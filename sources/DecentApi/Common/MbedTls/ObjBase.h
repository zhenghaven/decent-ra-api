#pragma once

#include <utility>

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

		/** \brief	An object base class for MbedTLS objects. */
		template<typename T>
		class ObjBase
		{
		public:
			/** \brief	Defines an alias representing the type of free function for m_ptr. */
			typedef void(*FreeFuncType)(T*);

			/**
			* \brief	An empty function which don't free the m_ptr.
			* 			This is necessary when this instance is not the real owner of
			* 			the MbedTLS object that this instance is holding.
			*
			* \param [in,out]	ptr	If non-null, the pointer.
			*/
			static void DoNotFree(T* ptr) noexcept { /*Do nothing.*/ }

		public:
			ObjBase() = delete;

			/**
			* \brief	Constructor
			* 			Usually this class is used internally, thus, it's the developer's responsibility to
			* 			make sure the value passed in is correct (e.g. not null).
			*
			* \param [in,out]	ptr			If non-null, the pointer to the MbedTLS object.
			* \param 		  	freeFunc	The free function to free the MbedTLS object *AND delete the pointer*.
			*/
			ObjBase(T* ptr, FreeFuncType freeFunc) noexcept :
			m_ptr(ptr),
				m_freeFunc(freeFunc)
			{}

			ObjBase(const ObjBase& other) = delete;

			/**
			* \brief	Move constructor
			*
			* \param [in,out]	other	The other instance.
			*/
			ObjBase(ObjBase&& rhs) noexcept :
				m_ptr(rhs.m_ptr),
				m_freeFunc(rhs.m_freeFunc)
			{
				rhs.m_ptr = nullptr;
				rhs.m_freeFunc = &DoNotFree;
			}

			virtual ObjBase& operator=(const ObjBase& other) = delete;

			/**
			* \brief	Move assignment operator
			*
			* \param [in,out]	other	The other instance.
			*
			* \return	A reference to this object.
			*/
			virtual ObjBase& operator=(ObjBase&& other) noexcept
			{
				if (this != &other)
				{
					T * tmpPtr = this->m_ptr;
					FreeFuncType tmpFreeFunc = this->m_freeFunc;

					this->m_ptr = other.m_ptr;
					this->m_freeFunc = other.m_freeFunc;

					other.m_ptr = tmpPtr;
					other.m_freeFunc = tmpFreeFunc;
				}
				return *this;
			}

			/** \brief	Destructor */
			virtual ~ObjBase()
			{
				(*m_freeFunc)(m_ptr);
				m_ptr = nullptr;
			}

			/**
			* \brief	Cast that converts this instance to a bool
			* 			This function basically check whether or not the pointer m_ptr is null.
			*
			* \return	True if m_ptr is not null, otherwise, false.
			*/
			virtual operator bool() const noexcept
			{
				return m_ptr != nullptr;
			}

			/**
			* \brief	Gets the pointer to the MbedTLS object.
			*
			* \return	The pointer to the MbedTLS object.
			*/
			T* Get() const noexcept
			{
				return m_ptr;
			}

			/**
			* \brief	Releases the ownership of the MbedTLS Object, and
			* 			return the pointer to the MbedTLS object.
			*
			* \return	The pointer to the MbedTLS object.
			*/
			T* Release() noexcept
			{
				T* tmp = m_ptr;

				m_ptr = nullptr;
				m_freeFunc = &DoNotFree;

				return tmp;
			}

			virtual void Swap(ObjBase& rhs) noexcept
			{
				ObjBase tmp(std::move(rhs));
				rhs = std::move(*this);
				*this = std::move(tmp);
			}

			/**
			* \brief	Query if this is the actual owner of MbedTLS object.
			*
			* \return	True if it's, false if not.
			*/
			virtual bool IsOwner() const noexcept
			{
				return m_freeFunc != &DoNotFree;
			}

		protected:
			void SetPtr(T* ptr) noexcept
			{
				m_ptr = ptr;
			}

		private:
			T * m_ptr;
			FreeFuncType m_freeFunc;
		};
	}
}
