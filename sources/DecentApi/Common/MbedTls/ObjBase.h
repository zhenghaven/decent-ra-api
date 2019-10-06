#pragma once

#include <utility>
#include "Initializer.h"
#include "MbedTlsCppDefs.h"
#include "RuntimeException.h"

namespace Decent
{
	namespace MbedTlsObj
	{
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
				m_freeFunc(freeFunc),
				m_mbedInit(Initializer::Init())
			{}

			ObjBase(const ObjBase& other) = delete;

			/**
			* \brief	Move constructor
			*
			* \param [in,out]	other	The other instance.
			*/
			ObjBase(ObjBase&& rhs) noexcept :
				m_ptr(rhs.m_ptr),
				m_freeFunc(rhs.m_freeFunc),
				m_mbedInit(Initializer::Init())
			{
				rhs.m_ptr = nullptr;
				rhs.m_freeFunc = &DoNotFree;
			}

			/** \brief	Destructor */
			virtual ~ObjBase()
			{
				(*m_freeFunc)(m_ptr);
				m_ptr = nullptr;
			}

			ObjBase& operator=(const ObjBase& other) = delete;

			/**
			 * \brief	Move assignment operator. The RHS will become null.
			 *
			 * \param [in,out]	rhs	The right hand side.
			 *
			 * \return	A reference to this object.
			 */
			ObjBase& operator=(ObjBase&& rhs)
			{
				if (this != &rhs)
				{
					//Free the object to prevent memory leak.
					Reset();

					m_ptr = rhs.m_ptr;
					m_freeFunc = rhs.m_freeFunc;

					rhs.m_ptr = nullptr;
					rhs.m_freeFunc = &DoNotFree;
				}
				return *this;
			}

			/**
			 * \brief	Swaps the given right hand side
			 *
			 * \param [in,out]	rhs	The right hand side.
			 */
			void Swap(ObjBase& rhs) noexcept
			{
				std::swap(m_ptr, rhs.m_ptr);
				std::swap(m_freeFunc, rhs.m_freeFunc);
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
			const T* Get() const noexcept
			{
				return m_ptr;
			}

			/**
			* \brief	Gets the pointer to the MbedTLS object.
			*
			* \return	The pointer to the MbedTLS object.
			*/
			T* Get() noexcept
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

			/**
			* \brief	Query if this is the actual owner of MbedTLS object.
			*
			* \return	True if it's, false if not.
			*/
			virtual bool IsOwner() const
			{
				return m_freeFunc != &DoNotFree;
			}

			/**
			 * \brief	Query if c object held by this object is null
			 *
			 * \return	True if null, false if not.
			 */
			virtual bool IsNull() const
			{
				return m_ptr == nullptr;
			}

			/**
			 * \brief	Check if the current instance is holding a null pointer for the mbedTLS object. If so,
			 * 			exception will be thrown. Helper function to be called before accessing the mbedTLS
			 * 			object.
			 *
			 * \exception	RuntimeException	Thrown when the current instance is holding a null pointer
			 * 									for the mbedTLS object.
			 */
			virtual void NullCheck() const
			{
				if (IsNull())
				{
					throw RuntimeException("Trying to access a null mbedTLS Cpp object.");
				}
			}

			// Will be put into mutable later.
			T* GetMutable() const noexcept
			{
				return m_ptr;
			}

		protected:
			void SetPtr(T* ptr) noexcept
			{
				m_ptr = ptr;
			}

			void SetFreeFunc(FreeFuncType freeFunc) noexcept
			{
				m_freeFunc = freeFunc;
			}

			/** \brief	Free the held object and Resets this instance to null state. */
			void Reset()
			{
				(*m_freeFunc)(m_ptr);

				m_ptr = nullptr;
				m_freeFunc = &DoNotFree;
			}

		private:
			T * m_ptr;
			FreeFuncType m_freeFunc;

			const Initializer& m_mbedInit;
		};
	}
}
